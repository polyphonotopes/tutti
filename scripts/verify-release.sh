#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

if ! git diff --quiet || ! git diff --cached --quiet ||
  [[ -n "$(git ls-files --others --exclude-standard)" ]]; then
  echo "release verification requires a clean, committed worktree" >&2
  exit 1
fi

echo "==> formatting"
cargo fmt --all -- --check
cargo fmt --manifest-path tutti-amy/Cargo.toml --all -- --check

echo "==> workspace tests"
cargo test --workspace --all-features --locked

echo "==> excluded AMY leaf tests"
cargo test --manifest-path tutti-amy/Cargo.toml --all-features --locked

echo "==> strict linting"
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo clippy --manifest-path tutti-amy/Cargo.toml --all-targets --all-features --locked -- -D warnings

echo "==> compiled documentation"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps --locked
RUSTDOCFLAGS="-D warnings" cargo doc \
  --manifest-path tutti-amy/Cargo.toml \
  --all-features \
  --no-deps \
  --locked

echo "==> wasm32 compile surface"
cargo check \
  --workspace \
  --all-targets \
  --all-features \
  --target wasm32-unknown-unknown \
  --locked

echo "==> fresh external consumer"
consumer_dir="$(mktemp -d "${TMPDIR:-/tmp}/tutti-consumer.XXXXXX")"
trap 'rm -rf "$consumer_dir"' EXIT
snapshot_dir="$consumer_dir/repository"
app_dir="$consumer_dir/app"
mkdir -p "$snapshot_dir" "$app_dir/src"
git archive --format=tar HEAD | tar -xf - -C "$snapshot_dir"
git -C "$snapshot_dir" init -q
git -C "$snapshot_dir" add .
git -C "$snapshot_dir" \
  -c user.name="Tutti release gate" \
  -c user.email="release-gate@invalid" \
  commit -q -m "Fresh consumer snapshot"
snapshot_rev="$(git -C "$snapshot_dir" rev-parse HEAD)"

cat >"$app_dir/Cargo.toml" <<EOF
[package]
name = "tutti-release-consumer"
version = "0.0.0"
edition = "2024"

[dependencies]
tutti-music-hhhs = { git = "file://$snapshot_dir", rev = "$snapshot_rev" }
EOF
cat >"$app_dir/src/main.rs" <<'EOF'
fn main() {
    assert!(tutti_music_hhhs::PROTOCOL_GENERATION > 0);
}
EOF
CARGO_TARGET_DIR="$consumer_dir/target" cargo generate-lockfile --manifest-path "$app_dir/Cargo.toml"
CARGO_TARGET_DIR="$consumer_dir/target" cargo check --manifest-path "$app_dir/Cargo.toml" --locked

echo "Tutti release verification passed."
