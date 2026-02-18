// SPDX-License-Identifier: CC0-1.0

use crate::{CompactSizeDecoder, CompactSizeEncoder, Decoder, Encoder};

fn compact_size_bytes(value: usize) -> ([u8; 9], usize) {
    let mut out = [0_u8; 9];
    let mut encoder = CompactSizeEncoder::new(value);
    let mut len = 0;
    loop {
        let chunk = encoder.current_chunk();
        out[len..len + chunk.len()].copy_from_slice(chunk);
        len += chunk.len();
        if !encoder.advance() {
            break;
        }
    }
    (out, len)
}

#[kani::unwind(12)]
#[kani::proof]
fn compact_size_roundtrip_u16() {
    let n: u16 = kani::any();
    let value = usize::from(n);
    let (encoded, encoded_len) = compact_size_bytes(value);
    let mut decoder = CompactSizeDecoder::new();
    let mut bytes = &encoded[..encoded_len];
    let done = decoder.push_bytes(&mut bytes).unwrap();

    assert!(!done);
    assert!(bytes.is_empty());
    assert_eq!(decoder.end().unwrap(), value);
}

#[kani::proof]
fn compact_size_rejects_non_minimal_encoding() {
    let mut decoder = CompactSizeDecoder::new();
    let mut bytes = &[0xFD, 0xFC, 0x00][..];
    let done = decoder.push_bytes(&mut bytes).unwrap();

    assert!(!done);
    assert!(bytes.is_empty());
    assert!(decoder.end().is_err());
}
