//! nxp-proto — NXP/0.1 wire primitives (prototype sketch).
//!
//! Binary framing (10-byte header, big-endian ints, LEB128 varints inside
//! payloads), signed content-addressed resource records, and an async frame
//! reader. Design rationale and wire-format sketch: ../protocol/NXP-0.1.md.
//!
//! Layout:
//! - `wire`: bounds-checked Reader/Writer over byte slices
//! - `frame`: 10-byte FrameHeader, FrameType, FETCH payload codec
//! - `record`: ResourceRecord (canonical bytes for signing, encode/decode)
//! - `codec`: async FrameReader/FrameWriter over any tokio AsyncRead/Write

pub mod codec;
pub mod frame;
pub mod record;
pub mod wire;