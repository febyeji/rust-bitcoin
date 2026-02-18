// SPDX-License-Identifier: CC0-1.0

#![cfg(feature = "alloc")]

use bitcoin_consensus_encoding::{
    ArrayDecoder, ArrayEncoder, ByteVecDecoder, ByteVecDecoderError, BytesEncoder, Decodable,
    Decoder, Decoder3, Decoder3Error, Encodable, Encoder2,
};

#[cfg(feature = "std")]
use bitcoin_consensus_encoding::decode_from_read_unbuffered;
use bitcoin_consensus_encoding::{decode_from_slice, encode_to_vec, CompactSizeEncoder};
#[cfg(feature = "std")]
use std::io::Cursor;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Packet {
    version: [u8; 4],
    payload: Vec<u8>,
    checksum: [u8; 4],
}

impl Encodable for Packet {
    type Encoder<'e>
        = Encoder2<
        ArrayEncoder<4>,
        Encoder2<CompactSizeEncoder, Encoder2<BytesEncoder<'e>, ArrayEncoder<4>>>,
    >
    where
        Self: 'e;

    fn encoder(&self) -> Self::Encoder<'_> {
        Encoder2::new(
            ArrayEncoder::without_length_prefix(self.version),
            Encoder2::new(
                CompactSizeEncoder::new(self.payload.len()),
                Encoder2::new(
                    BytesEncoder::without_length_prefix(&self.payload),
                    ArrayEncoder::without_length_prefix(self.checksum),
                ),
            ),
        )
    }
}

struct PacketDecoder {
    inner: Decoder3<ArrayDecoder<4>, ByteVecDecoder, ArrayDecoder<4>>,
}

impl Decodable for Packet {
    type Decoder = PacketDecoder;

    fn decoder() -> Self::Decoder {
        Self::Decoder {
            inner: Decoder3::new(ArrayDecoder::new(), ByteVecDecoder::new(), ArrayDecoder::new()),
        }
    }
}

impl Decoder for PacketDecoder {
    type Output = Packet;
    type Error = Decoder3Error<
        bitcoin_consensus_encoding::UnexpectedEofError,
        ByteVecDecoderError,
        bitcoin_consensus_encoding::UnexpectedEofError,
    >;

    fn push_bytes(&mut self, bytes: &mut &[u8]) -> Result<bool, Self::Error> {
        self.inner.push_bytes(bytes)
    }

    fn end(self) -> Result<Self::Output, Self::Error> {
        let (version, payload, checksum) = self.inner.end()?;
        Ok(Packet { version, payload, checksum })
    }

    fn read_limit(&self) -> usize {
        self.inner.read_limit()
    }
}

fn decode_chunked(data: &[u8], chunk: usize) -> Result<Packet, <PacketDecoder as Decoder>::Error> {
    let mut decoder = Packet::decoder();
    let mut remaining = data;
    while !remaining.is_empty() {
        let take = chunk.min(remaining.len());
        let (head, tail) = remaining.split_at(take);
        remaining = tail;
        let mut buf = head;
        let needs_more = decoder.push_bytes(&mut buf)?;
        assert!(buf.is_empty(), "decoder must fully consume each provided chunk");
        if !needs_more {
            return decoder.end();
        }
    }
    decoder.end()
}

#[test]
fn vector_packet_roundtrip_small_payload() {
    let vector = [
        0x01, 0x00, 0x00, 0x00, // version
        0x03, // compact size payload length
        0xAA, 0xBB, 0xCC, // payload bytes
        0xDE, 0xAD, 0xBE, 0xEF, // checksum
    ];

    let packet = decode_from_slice::<Packet>(&vector).expect("valid vector must decode");
    assert_eq!(packet.version, [1, 0, 0, 0]);
    assert_eq!(packet.payload, vec![0xAA, 0xBB, 0xCC]);
    assert_eq!(packet.checksum, [0xDE, 0xAD, 0xBE, 0xEF]);
    assert_eq!(encode_to_vec(&packet), vector);
}

#[test]
fn vector_packet_roundtrip_compact_size_fd_boundary() {
    let payload = vec![0x42; 0xFD];
    let packet = Packet { version: [2, 0, 0, 0], payload: payload.clone(), checksum: [9, 8, 7, 6] };
    let encoded = encode_to_vec(&packet);

    assert_eq!(&encoded[..7], &[2, 0, 0, 0, 0xFD, 0xFD, 0x00]);
    let decoded = decode_from_slice::<Packet>(&encoded).expect("boundary vector must decode");
    assert_eq!(decoded, packet);
}

#[test]
fn vector_packet_rejects_non_minimal_compact_size_length() {
    let vector = [
        0x01, 0x00, 0x00, 0x00, // version
        0xFD, 0xFC, 0x00, // non-minimal payload length (252 should be encoded in one byte)
        0xDE, 0xAD, 0xBE, 0xEF, // checksum bytes that should not rescue decoding
    ];
    let err = decode_from_slice::<Packet>(&vector).expect_err("non-minimal compact size must fail");
    assert!(matches!(err, Decoder3Error::Second(_)));
}

#[test]
fn vector_packet_rejects_truncated_payload() {
    let vector = [
        0x01, 0x00, 0x00, 0x00, // version
        0x03, // payload length
        0xAA, // payload truncated (needs two more bytes)
    ];
    let err = decode_from_slice::<Packet>(&vector).expect_err("truncated payload must fail");
    assert!(matches!(err, Decoder3Error::Second(_)));
}

#[test]
fn vector_packet_chunked_decoder_matches_slice_decoder() {
    let packet = Packet {
        version: [3, 0, 0, 0],
        payload: (0_u8..=31).collect(),
        checksum: [0xAA, 0xBB, 0xCC, 0xDD],
    };
    let bytes = encode_to_vec(&packet);

    let slice_decoded = decode_from_slice::<Packet>(&bytes).expect("slice decode");
    for chunk in [1_usize, 2, 5, 8, 64] {
        let chunked = decode_chunked(&bytes, chunk).expect("chunked decode");
        assert_eq!(chunked, slice_decoded, "chunk size {chunk}");
    }
}

#[test]
#[cfg(feature = "std")]
fn vector_packet_read_decoder_matches_slice_decoder() {
    let packet =
        Packet { version: [9, 0, 0, 0], payload: vec![1, 2, 3, 4, 5, 6], checksum: [7, 8, 9, 10] };
    let bytes = encode_to_vec(&packet);

    let slice_decoded = decode_from_slice::<Packet>(&bytes).expect("slice decode");
    let read_decoded = decode_from_read_unbuffered::<Packet, _>(Cursor::new(bytes.as_slice()))
        .expect("read decode");
    assert_eq!(slice_decoded, read_decoded);
}
