// This file is part of SafeXNetwork.

// Copyright (C) SafeXNetwork (HK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

// 	http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use sp_core::bounded::alloc::string::{String, ToString};
use bls_signatures::{verify as verify_bls_sig, Serialize};

pub fn bls_verify(pubkey: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), String> {
    let pk = bls_signatures::PublicKey::from_bytes(&pubkey).map_err(|e| e.to_string())?;
    // generate signature struct from bytes
    let sig = bls_signatures::Signature::from_bytes(sig).map_err(|e| e.to_string())?;
    let hashed = bls_signatures::hash(&msg);
    // BLS verify hash against key
    if !verify_bls_sig(&sig, &[hashed], &[pk]) {
        return Err("bls signature verify failed".to_string());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bls_signatures::{PrivateKey, Serialize};

    #[test]
    fn test_bls_verify_success() {
        let seed = b"this is a test seed for bls -- 32 bytes!";
        let privkey = PrivateKey::new(seed);
        let pubkey = privkey.public_key();
        let message = b"test message for bls verification";
        let signature = privkey.sign(message);

        let pubkey_bytes = pubkey.as_bytes();
        let sig_bytes = signature.as_bytes();

        let result = bls_verify(&pubkey_bytes, message, &sig_bytes);
        assert!(result.is_ok(), "bls_verify should succeed: {:?}", result);
    }

    #[test]
    fn test_bls_verify_wrong_message() {
        let seed = b"this is a test seed for bls -- 32 bytes!";
        let privkey = PrivateKey::new(seed);
        let pubkey = privkey.public_key();
        let message = b"test message for bls verification";
        let signature = privkey.sign(message);

        let pubkey_bytes = pubkey.as_bytes();
        let sig_bytes = signature.as_bytes();

        let wrong_message = b"this is a different message";
        let result = bls_verify(&pubkey_bytes, wrong_message, &sig_bytes);
        assert!(result.is_err(), "bls_verify should fail with wrong message");
    }

    #[test]
    fn test_bls_verify_wrong_signature() {
        let seed = b"this is a test seed for bls -- 32 bytes!";
        let privkey = PrivateKey::new(seed);
        let pubkey = privkey.public_key();
        let message = b"test message for bls verification";

        // Sign a different message to produce an incorrect signature
        let wrong_signature = privkey.sign(b"different message");

        let pubkey_bytes = pubkey.as_bytes();
        let sig_bytes = wrong_signature.as_bytes();

        let result = bls_verify(&pubkey_bytes, message, &sig_bytes);
        assert!(
            result.is_err(),
            "bls_verify should fail with wrong signature"
        );
    }

    #[test]
    fn test_bls_verify_invalid_pubkey_bytes() {
        let invalid_pubkey = vec![0u8; 48];
        let message = b"test message";
        let sig = vec![0u8; 96];

        let result = bls_verify(&invalid_pubkey, message, &sig);
        assert!(
            result.is_err(),
            "bls_verify should fail with invalid pubkey bytes"
        );
    }

    #[test]
    fn test_bls_verify_invalid_signature_bytes() {
        let seed = b"this is a test seed for bls -- 32 bytes!";
        let privkey = PrivateKey::new(seed);
        let pubkey = privkey.public_key();
        let message = b"test message";

        let invalid_sig = vec![0u8; 96];

        let pubkey_bytes = pubkey.as_bytes();
        let result = bls_verify(&pubkey_bytes, message, &invalid_sig);
        assert!(
            result.is_err(),
            "bls_verify should fail with invalid signature bytes"
        );
    }
}
