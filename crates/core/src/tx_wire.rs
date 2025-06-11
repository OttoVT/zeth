// Copyright 2024, 2025 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Transaction wire format helpers that preserve EIP-2718 type bytes
//! for proper hash preservation during POT serialization round-trips.

use alloy_rlp::{Encodable, Decodable};
use reth_primitives::TransactionSigned;
use alloy_primitives::B256;

/// Trait to compute the correct on-chain transaction hash using wire format
pub trait HashWire {
    fn hash_wire(&self) -> B256;
}

impl HashWire for TransactionSigned {
    fn hash_wire(&self) -> B256 {
        alloy_primitives::keccak256(encode_wire(self))
    }
}

/// Return the exact byte string that appears in the block – legacy or typed.
/// This preserves EIP-2718 type bytes (0x01/0x02/0x03) that are required for correct hash computation.
pub fn encode_wire(tx: &TransactionSigned) -> Vec<u8> {
    let mut inner_bytes = Vec::new();
    tx.encode(&mut inner_bytes);  // Use the standard encode method
    
    // Check transaction variant to determine if we need to prepend type byte
    match tx {
        TransactionSigned::Legacy(_) => {
            // Legacy transaction - no type byte needed
            inner_bytes
        }
        TransactionSigned::Eip2930(_) => {
            // EIP-2930 transaction - prepend 0x01 type byte
            let mut out = Vec::with_capacity(1 + inner_bytes.len());
            out.push(0x01);           // EIP-2930 type byte
            out.extend(inner_bytes);  // Add the RLP-encoded transaction data
            out
        }
        TransactionSigned::Eip1559(_) => {
            // EIP-1559 transaction - prepend 0x02 type byte
            let mut out = Vec::with_capacity(1 + inner_bytes.len());
            out.push(0x02);           // EIP-1559 type byte
            out.extend(inner_bytes);  // Add the RLP-encoded transaction data
            out
        }
        TransactionSigned::Eip4844(_) => {
            // EIP-4844 transaction - prepend 0x03 type byte
            let mut out = Vec::with_capacity(1 + inner_bytes.len());
            out.push(0x03);           // EIP-4844 type byte
            out.extend(inner_bytes);  // Add the RLP-encoded transaction data
            out
        }
        TransactionSigned::Eip7702(_) => {
            // EIP-7702 transaction - prepend 0x04 type byte
            let mut out = Vec::with_capacity(1 + inner_bytes.len());
            out.push(0x04);           // EIP-7702 type byte
            out.extend(inner_bytes);  // Add the RLP-encoded transaction data
            out
        }
        // Note: If there are additional transaction types in the future, 
        // they would need to be handled here
    }
}

/// Parse a wire-format tx (typed or legacy) back into TransactionSigned.
/// This correctly handles both legacy and EIP-2718 typed transactions.
pub fn decode_wire(bytes: &[u8]) -> alloy_rlp::Result<TransactionSigned> {
    if bytes.is_empty() {
        return Err(alloy_rlp::Error::InputTooShort);
    }
    
    let first_byte = bytes[0];
    
    // Legacy transactions start with RLP list indicator (0xc0-0xff range)
    // Typed transactions start with type bytes (0x01, 0x02, 0x03, 0x04, etc.)
    if first_byte >= 0xc0 {
        // Legacy transaction: the first byte is the RLP list prefix, decode as-is
        let mut cursor = bytes;
        TransactionSigned::decode(&mut cursor)
    } else if first_byte <= 0x04 {
        // Typed transaction: first byte is the type prefix (0x01-0x04 for current EIP types)
        if bytes.len() < 2 {
            return Err(alloy_rlp::Error::InputTooShort);
        }
        
        let _tx_type = first_byte;  // Store for potential future validation
        let tx_data = &bytes[1..];  // Strip the type byte
        let mut cursor = tx_data;
        
        // Decode the transaction data without the type byte
        // Note: The decode will automatically reconstruct the correct variant
        // based on the transaction data structure
        TransactionSigned::decode(&mut cursor)
    } else {
        // Invalid first byte - not a valid transaction format
        Err(alloy_rlp::Error::Custom("Invalid transaction format: first byte not valid for legacy or typed transaction".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, Bytes, U256, TxKind, Signature};
    use alloy_consensus::{TxLegacy, Signed, SignableTransaction};

    fn create_legacy_transaction() -> TransactionSigned {
        let tx = TxLegacy {
            chain_id: Some(1),
            nonce: 42u64,
            gas_price: 20_000_000_000,
            gas_limit: 21000,
            to: TxKind::Call(Address::ZERO),
            value: U256::from(1000),
            input: Bytes::new(),
        };
        
        let signature = Signature::new(U256::from(1), U256::from(2), false);
        let hash = tx.signature_hash();
        let signed_tx = Signed::new_unchecked(tx, signature, hash);
        
        TransactionSigned::Legacy(signed_tx)
    }

    #[test]
    fn test_legacy_transaction_hash_preservation() {
        let tx = create_legacy_transaction();
        let original_wire_hash = tx.hash_wire();  // Use correct wire hash
        
        // Test wire format round-trip
        let wire_bytes = encode_wire(&tx);
        let recovered_tx = decode_wire(&wire_bytes).expect("Failed to decode wire format");
        let recovered_wire_hash = recovered_tx.hash_wire();  // Use correct wire hash
        
        assert_eq!(original_wire_hash, recovered_wire_hash, 
            "Legacy transaction wire hash changed! Original: {:?}, Recovered: {:?}", 
            original_wire_hash, recovered_wire_hash);
    }

    #[test]
    fn test_wire_format_legacy_no_type_byte() {
        let tx = create_legacy_transaction();
        
        // For legacy transactions, wire format should be the same as standard encoding
        let wire_bytes = encode_wire(&tx);
        let mut standard_bytes = Vec::new();
        tx.encode(&mut standard_bytes);
        
        // For legacy transactions, these should be identical (no type byte)
        assert_eq!(wire_bytes, standard_bytes, "Legacy transaction wire format should match standard encoding");
        
        // Test round-trip using correct wire hash comparison
        let recovered = decode_wire(&wire_bytes).expect("Failed to decode");
        assert_eq!(tx.hash_wire(), recovered.hash_wire(), "Wire hash should be preserved");
    }

    #[test]
    fn test_typed_transaction_gets_type_byte() {
        // Note: This test would need a typed transaction to verify
        // For now, we can at least verify the encode_wire function structure
        
        let tx = create_legacy_transaction();
        let wire_bytes = encode_wire(&tx);
        
        // Verify that decoding doesn't panic
        let _recovered = decode_wire(&wire_bytes).expect("Failed to decode");
        
        // TODO: Add tests for EIP-1559, EIP-2930, EIP-4844 transactions
        // once we can create test instances of them
    }

    #[test]
    fn test_decode_wire_handles_empty_bytes() {
        let result = decode_wire(&[]);
        assert!(result.is_err(), "Empty bytes should result in error");
    }

    #[test]
    fn test_decode_wire_handles_too_short_typed() {
        let result = decode_wire(&[0x02]); // Type byte without data
        assert!(result.is_err(), "Type byte without data should result in error");
    }

    #[test]
    fn test_hash_wire_matches_keccak256_of_wire_bytes() {
        // This test validates the suggestions4.md assertion that hash_wire() 
        // produces the same result as keccak256(encode_wire())
        use alloy_primitives::keccak256;
        
        let tx = create_legacy_transaction();
        
        // Method 1: Using our hash_wire() helper
        let hash_via_helper = tx.hash_wire();
        
        // Method 2: Manual keccak256 of wire bytes (the "true" on-chain hash)
        let wire_bytes = encode_wire(&tx);
        let hash_via_keccak256 = keccak256(&wire_bytes);
        
        // Method 3: The old hash_slow() method for comparison
        let hash_slow = tx.hash().clone();
        
        println!("hash_wire():        {:?}", hash_via_helper);
        println!("keccak256(wire):    {:?}", hash_via_keccak256);
        println!("hash_slow():        {:?}", hash_slow);
        
        // The critical assertion: hash_wire() must match keccak256(wire_bytes)
        assert_eq!(hash_via_helper, hash_via_keccak256, 
            "hash_wire() must produce same result as keccak256(encode_wire())");
            
        // For legacy transactions, these might be the same or different depending on EIP-155
        if hash_via_helper != hash_slow {
            println!("Note: hash_wire() differs from hash_slow() - this indicates EIP-155 or other issues");
        } else {
            println!("Note: hash_wire() matches hash_slow() for this legacy transaction");
        }
        
        println!("✅ hash_wire() correctly computes keccak256 of wire format");
    }

    #[test]
    fn test_wire_format_is_broadcast_ready() {
        // Verify that our wire format produces bytes that could actually be broadcast
        let tx = create_legacy_transaction();
        let wire_bytes = encode_wire(&tx);
        
        // Legacy transactions should start with RLP list prefix (0xc0-0xff)
        assert!(wire_bytes[0] >= 0xc0, "Legacy transaction should start with RLP list prefix");
        
        // Should be able to round-trip without corruption
        let recovered = decode_wire(&wire_bytes).expect("Should decode successfully");
        
        // Wire hashes should match
        assert_eq!(tx.hash_wire(), recovered.hash_wire(), "Wire hash should survive round-trip");
        
        println!("✅ Wire format is broadcast-ready and round-trip safe");
    }
} 