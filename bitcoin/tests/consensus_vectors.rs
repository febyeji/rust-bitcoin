// SPDX-License-Identifier: CC0-1.0

//! Roundtrip tests for Bitcoin Core's tx_valid.json using the new consensus encoding traits.

use bitcoin::Transaction;
use bitcoin::hex::FromHex;

/// Parses Bitcoin Core's tx_valid.json and roundtrip-tests every valid transaction
/// vector through the new consensus encoding traits (decode → re-encode → compare bytes).
#[test]
fn tx_valid_roundtrip() {
    let json_str = include_str!("data/tx_valid.json");
    let entries: Vec<serde_json::Value> = serde_json::from_str(json_str).expect("valid JSON");

    let mut tested = 0;

    for entry in &entries {
        let arr = match entry.as_array() {
            Some(a) => a,
            None => continue,
        };

        // Test cases have 3 elements: [[inputs...], "tx_hex", "flags"].
        // Comment-only entries are ["string"] (1 element with a string).
        if arr.len() != 3 {
            continue;
        }

        // The second element must be a string (the serialized transaction hex).
        let tx_hex = match arr[1].as_str() {
            Some(s) => s,
            None => continue,
        };

        let tx_bytes: Vec<u8> = Vec::from_hex(tx_hex)
            .unwrap_or_else(|e| panic!("invalid hex in test vector: {e}"));

        // Decode using the new consensus encoding traits.
        let tx: Transaction = encoding::decode_from_slice(&tx_bytes)
            .unwrap_or_else(|e| panic!("failed to decode tx {tx_hex}: {e}"));

        // Re-encode and verify roundtrip byte equality.
        let re_encoded = encoding::encode_to_vec(&tx);
        assert_eq!(
            tx_bytes, re_encoded,
            "roundtrip mismatch for tx {}",
            tx.compute_txid()
        );

        // Sanity: compute_txid should not panic.
        let _txid = tx.compute_txid();

        tested += 1;
    }

    assert!(tested > 100, "expected >100 valid tx vectors, got {tested}");
}
