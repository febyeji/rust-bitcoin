// SPDX-License-Identifier: CC0-1.0

//! Raw PSBT key-value pairs.
//!
//! Raw PSBT key-value pairs as defined at
//! <https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>.

use core::fmt;

#[cfg(feature = "arbitrary")]
use arbitrary::{Arbitrary, Unstructured};
use internals::ToU64 as _;
use io::{BufRead, Write};

use super::serialize::{Deserialize, Serialize};
use crate::consensus::encode::{
    self, deserialize, serialize, Decodable, Encodable, ReadExt, WriteExt, MAX_VEC_SIZE,
};
use crate::consensus::parse_failed_error;
use crate::prelude::{DisplayHex, Vec};
use crate::psbt::Error;

/// A PSBT key in its raw byte form.
///
/// `<key> := <keylen> <keytype> <keydata>`
#[derive(Debug, PartialEq, Hash, Eq, Clone, Ord, PartialOrd)]
pub struct Key {
    /// The type of this PSBT key.
    pub type_value: u64, // Encoded as a compact size.
    /// The key data itself in raw byte form.
    pub key_data: Vec<u8>,
}

/// A PSBT key-value pair in its raw byte form.
/// `<keypair> := <key> <value>`
#[derive(Debug, PartialEq, Eq)]
pub struct Pair {
    /// The key of this key-value pair.
    pub key: Key,
    /// The value data of this key-value pair in raw byte form.
    /// `<value> := <valuelen> <valuedata>`
    pub value: Vec<u8>,
}

/// Default implementation for proprietary key subtyping
pub type ProprietaryType = u64;

/// Proprietary keys (i.e. keys starting with 0xFC byte) with their internal
/// structure according to BIP 174.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ProprietaryKey<Subtype = ProprietaryType>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    /// Proprietary type prefix used for grouping together keys under some
    /// application and avoid namespace collision
    pub prefix: Vec<u8>,
    /// Custom proprietary subtype
    pub subtype: Subtype,
    /// Additional key bytes (like serialized public key data etc)
    pub key: Vec<u8>,
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "type: {:#x}, key: {:x}", self.type_value, self.key_data.as_hex())
    }
}

/// Returns the number of bytes needed to encode `n` as a Bitcoin compact size.
fn compact_size_len(n: u64) -> usize {
    match n {
        0..=0xFC => 1,
        0xFD..=0xFFFF => 3,
        0x1_0000..=0xFFFF_FFFF => 5,
        _ => 9,
    }
}

impl Key {
    pub(crate) fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let byte_size = r.read_compact_size()?;

        if byte_size == 0 {
            return Err(Error::NoMorePairs);
        }

        let type_value = r.read_compact_size()?;
        let type_value_len = compact_size_len(type_value) as u64;

        if byte_size < type_value_len {
            return Err(parse_failed_error(
                "PSBT key length shorter than compact size encoding of type value",
            )
            .into());
        }

        let key_byte_size = byte_size - type_value_len;

        if key_byte_size > MAX_VEC_SIZE.to_u64() {
            return Err(encode::Error::Parse(encode::ParseError::OversizedVectorAllocation {
                requested: key_byte_size as usize,
                max: MAX_VEC_SIZE,
            })
            .into());
        }

        let mut key_data = Vec::with_capacity(key_byte_size as usize);
        for _ in 0..key_byte_size {
            key_data.push(Decodable::consensus_decode(r)?);
        }

        Ok(Self { type_value, key_data })
    }
}

impl Serialize for Key {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.emit_compact_size(self.key_data.len() + compact_size_len(self.type_value))
            .expect("in-memory writers don't error");

        buf.emit_compact_size(self.type_value).expect("in-memory writers don't error");

        for key in &self.key_data {
            key.consensus_encode(&mut buf).expect("in-memory writers don't error");
        }

        buf
    }
}

impl Serialize for Pair {
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend(self.key.serialize());
        // <value> := <valuelen> <valuedata>
        self.value.consensus_encode(&mut buf).unwrap();
        buf
    }
}

impl Deserialize for Pair {
    fn deserialize(bytes: &[u8]) -> Result<Self, Error> {
        let mut decoder = bytes;
        Self::decode(&mut decoder)
    }
}

impl Pair {
    pub(crate) fn decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self { key: Key::decode(r)?, value: Decodable::consensus_decode(r)? })
    }
}

impl<Subtype> Encodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.prefix.consensus_encode(w)?;
        len += w.emit_compact_size(self.subtype.into())?;
        w.write_all(&self.key)?;
        len += self.key.len();
        Ok(len)
    }
}

impl<Subtype> Decodable for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let prefix = Vec::<u8>::consensus_decode(r)?;
        let subtype = Subtype::from(r.read_compact_size()?);

        // The limit is a DOS protection mechanism the exact value is not
        // important, 1024 bytes is bigger than any key should be.
        let mut key = vec![];
        let _ = io::Read::read_to_limit(r, &mut key, 1024)?;

        Ok(Self { prefix, subtype, key })
    }
}

impl<Subtype> ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    /// Constructs a new full [Key] corresponding to this proprietary key type
    pub fn to_key(&self) -> Key { Key { type_value: 0xFC, key_data: serialize(self) } }
}

impl<Subtype> TryFrom<Key> for ProprietaryKey<Subtype>
where
    Subtype: Copy + From<u64> + Into<u64>,
{
    type Error = Error;

    /// Constructs a new [`ProprietaryKey`] from a [`Key`].
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidProprietaryKey`] if `key` does not start with `0xFC` byte.
    fn try_from(key: Key) -> Result<Self, Self::Error> {
        if key.type_value != 0xFC {
            return Err(Error::InvalidProprietaryKey);
        }

        Ok(deserialize(&key.key_data)?)
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for ProprietaryKey {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self {
            prefix: Vec::<u8>::arbitrary(u)?,
            subtype: u64::arbitrary(u)?,
            key: Vec::<u8>::arbitrary(u)?,
        })
    }
}

#[cfg(feature = "arbitrary")]
impl<'a> Arbitrary<'a> for Key {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(Self { type_value: u.arbitrary()?, key_data: Vec::<u8>::arbitrary(u)? })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key_roundtrip(type_value: u64, key_data: Vec<u8>) {
        let key = Key { type_value, key_data };
        let serialized = key.serialize();
        let mut cursor = io::Cursor::new(&serialized);
        let deserialized = Key::decode(&mut cursor).expect("roundtrip decode failed");
        assert_eq!(key, deserialized);
    }

    #[test]
    fn key_roundtrip_small_type() {
        // type_value = 0x0F uses 1-byte compact size encoding.
        key_roundtrip(0x0F, vec![0xAB, 0xCD]);
    }

    #[test]
    fn key_roundtrip_large_type() {
        // type_value = 0xFD (253) uses 3-byte compact size encoding.
        key_roundtrip(0xFD, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn key_roundtrip_very_large_type() {
        // type_value = 0x10000 uses 5-byte compact size encoding.
        key_roundtrip(0x1_0000, vec![0xFF]);
    }

    #[test]
    fn key_roundtrip_boundary_type() {
        // type_value = 0xFC (252) is the last value using 1-byte compact size encoding.
        // 0xFD (253) is the first to use 3-byte encoding. Test the boundary.
        key_roundtrip(0xFC, vec![0x01, 0x02]);
    }

    #[test]
    fn key_decode_keylen_too_short_for_type() {
        // Hand-craft bytes where keylen = 1 but type_value starts with 0xFD prefix,
        // which requires 3 bytes. The declared key length is inconsistent.
        //   keylen = 1 (compact size: 0x01)
        //   type_value encoding: 0xFD, 0xFD, 0x00 (253 as compact size)
        let bytes: Vec<u8> = vec![0x01, 0xFD, 0xFD, 0x00];
        let mut cursor = io::Cursor::new(&bytes);
        let result = Key::decode(&mut cursor);
        assert!(result.is_err(), "should fail when keylen is shorter than type encoding");
    }

    #[test]
    fn key_serialize_large_type_has_correct_keylen() {
        // type_value = 0xFD (253) needs 3 bytes for compact size encoding.
        // With 3 bytes of key_data, keylen should be 3 + 3 = 6, not 3 + 1 = 4.
        let key = Key { type_value: 0xFD, key_data: vec![0x01, 0x02, 0x03] };
        let serialized = key.serialize();
        // First byte is keylen encoded as compact size; 6 < 253 so it's a single byte.
        assert_eq!(serialized[0], 6);
    }

    #[test]
    fn key_decode_correctly_encoded_large_type() {
        // Hand-craft correctly encoded bytes for type_value=0xFD, key_data=[0x01, 0x02, 0x03]:
        //   keylen = 6 (compact size: 0x06)
        //   type_value = 253 (compact size: 0xFD, 0xFD, 0x00)
        //   key_data = [0x01, 0x02, 0x03]
        let bytes: Vec<u8> = vec![0x06, 0xFD, 0xFD, 0x00, 0x01, 0x02, 0x03];
        let mut cursor = io::Cursor::new(&bytes);
        let key = Key::decode(&mut cursor).expect("decode failed");
        assert_eq!(key.type_value, 0xFD);
        assert_eq!(key.key_data, vec![0x01, 0x02, 0x03]);
        // Verify entire input was consumed.
        assert_eq!(cursor.position() as usize, bytes.len());
    }
}
