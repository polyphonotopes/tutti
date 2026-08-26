#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

echo "==> formatting"
cargo fmt --all -- --check
cargo fmt --manifest-path tutti-amy/Cargo.toml --all -- --check

echo "==> workspace tests"
cargo test --workspace --all-features

echo "==> excluded AMY leaf tests"
cargo test --manifest-path tutti-amy/Cargo.toml --all-features

echo "==> strict linting"
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo clippy --manifest-path tutti-amy/Cargo.toml --all-targets --all-features -- -D warnings

echo "==> compiled documentation"
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --all-features --no-deps
RUSTDOCFLAGS="-D warnings" cargo doc \
  --manifest-path tutti-amy/Cargo.toml \
  --all-features \
  --no-deps

echo "==> wasm32 compile surface"
cargo check \
  --workspace \
  --all-targets \
  --all-features \
  --target wasm32-unknown-unknown

echo "==> fresh external consumer"
consumer_dir="$(mktemp -d "${TMPDIR:-/tmp}/tutti-consumer.XXXXXX")"
trap 'rm -rf "$consumer_dir"' EXIT
snapshot_dir="$consumer_dir/repository"
app_dir="$consumer_dir/app"
mkdir -p "$snapshot_dir" "$app_dir/src"
while IFS= read -r -d '' file; do
  mkdir -p "$snapshot_dir/$(dirname "$file")"
  cp -p "$file" "$snapshot_dir/$file"
done < <(git ls-files -co --exclude-standard -z)
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
CARGO_TARGET_DIR="$consumer_dir/target" cargo check --manifest-path "$app_dir/Cargo.toml"

echo "Tutti release verification passed."
