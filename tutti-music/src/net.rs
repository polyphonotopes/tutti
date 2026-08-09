//! Music-lane network identities.
//!
//! The constants a peer needs to join a room's music lane over range-based set
//! reconciliation — kept here, in the music protocol crate, so an independently
//! built peer (an ESP32 running only this crate) speaks the exact same
//! anti-entropy contract as a full host, without depending on the host.
//!
//! The lane is the authenticated ALPN itself: a peer that doesn't speak music
//! never gets past QUIC negotiation, so no music byte reaches it and no
//! extension byte reaches a music-only peer. Pair [`MUSIC_STRATEGY_NAME`] with
//! [`LANE_STRATEGY_VERSION`] to form the session's `StrategyId`.

/// ALPN for the music lane's range-based set reconciliation.
pub const MUSIC_RBSR_ALPN: &[u8] = b"tutti/music/rbsr/3";

/// RBSR strategy name for the music lane.
pub const MUSIC_STRATEGY_NAME: &str = "tutti-music-entryhash";

/// Generation of the lane anti-entropy contract. Distinct from
/// [`crate::lang::MusicLang`]'s wire schema, which stays pinned — only the
/// repair/discovery generation moves.
pub const LANE_STRATEGY_VERSION: u32 = 3;
