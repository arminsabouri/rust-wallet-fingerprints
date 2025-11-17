use std::collections::HashSet;

use bitcoin::{ecdsa::Signature as EcdsaSignature, Amount, OutPoint, PublicKey, Transaction};

use crate::{
    util::{extract_all_signatures, OutputType},
    TxOutWithOutpoint,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InputWithAmount {
    amount: Amount,
    outpoint: OutPoint,
}

/// Returns the input sorting types detected in the transaction
pub(crate) fn get_input_order(
    tx: &Transaction,
    prev_outs: &[TxOutWithOutpoint],
) -> Vec<InputSortingType> {
    if tx.input.len() == 1 {
        return vec![InputSortingType::Single];
    }

    let mut sorting_types = Vec::new();
    let mut amounts = Vec::new();

    // Collect amounts and prevouts
    for input in &tx.input {
        let prevout = prev_outs
            .iter()
            .find(|prevout| prevout.outpoint == input.previous_output)
            .expect("Previous transaction should always exist");
        amounts.push(InputWithAmount {
            amount: prevout.txout.value,
            outpoint: input.previous_output,
        });
    }

    // Check if amounts are sorted
    if !amounts.is_empty() {
        let mut sorted_amounts = amounts.clone();
        sorted_amounts.sort_by_key(|a| a.amount);
        if amounts == sorted_amounts {
            sorting_types.push(InputSortingType::Ascending);
        }

        sorted_amounts.reverse();
        if amounts == sorted_amounts {
            sorting_types.push(InputSortingType::Descending);
        }
    }

    // Check BIP69 sorting
    let orignial_prevout = tx.input.clone();
    let mut sorted_prevouts = tx.input.clone();
    sorted_prevouts.sort_by(|a, b| {
        let txid1 = hex::decode(a.previous_output.txid.to_string()).unwrap();
        let txid2 = hex::decode(b.previous_output.txid.to_string()).unwrap();
        txid1
            .cmp(&txid2)
            .then_with(|| a.previous_output.vout.cmp(&b.previous_output.vout))
    });
    if orignial_prevout == sorted_prevouts {
        sorting_types.push(InputSortingType::Bip69);
    }

    // Note: Historical sorting would require access to confirmation height data
    // which isn't available yet in this API
    if sorting_types.is_empty() {
        sorting_types.push(InputSortingType::Unknown);
    }

    sorting_types
}

/// Returns true if the transaction has low-order R-grinding signatures
/// https://bitcoinops.org/en/topics/low-r-grinding
pub(crate) fn low_order_r_grinding(tx: &Transaction) -> bool {
    let sigs = extract_all_signatures(tx);
    for sig_bytes in sigs.iter() {
        // TODO need to deal with compact schnorr sigs
        let sig = EcdsaSignature::from_slice(sig_bytes).unwrap();
        let compact = sig.to_vec();
        if compact[0] < 0x80 {
            return true;
        }
    }

    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum InputSortingType {
    /// Single input
    Single,
    /// Inputs are sorted in ascending order
    Ascending,
    /// Inputs are sorted in descending order
    Descending,
    /// Inputs are sorted according to BIP 69
    Bip69,
    // TODO: current unused. If we have confirmation height on input, we can use this
    Historical,
    /// Input sorting type is unknown
    Unknown,
}

pub(crate) fn get_input_types(
    tx: &Transaction,
    prev_outs: &[TxOutWithOutpoint],
) -> Vec<OutputType> {
    let mut input_types = Vec::new();
    for input in tx.input.iter() {
        let prev_out = &prev_outs
            .iter()
            .find(|txout| txout.outpoint == input.previous_output)
            .expect("Previous transaction should always exist");
        input_types.push(prev_out.get_type());
    }

    input_types
}

/// Returns true if the transaction has mixed input types
pub(crate) fn mixed_input_types(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> bool {
    let input_types = get_input_types(tx, prev_outs)
        .into_iter()
        .collect::<HashSet<OutputType>>();
    input_types.len() > 1
}

/// Returns true if the spending script pubkey has an uncompressed pubkey
pub(crate) fn spending_spk_has_uncompressed_pubkey(
    spending_tx: &Transaction,
    prev_outs: &[TxOutWithOutpoint],
) -> bool {
    for input in spending_tx.input.iter() {
        let prev_out = &prev_outs
            .iter()
            .find(|txout| txout.outpoint == input.previous_output)
            .expect("Previous transaction should always exist")
            .txout;
        if let Some(pubkey) = prev_out.script_pubkey.p2pk_public_key() {
            if !pubkey.compressed {
                return true;
            }
        }
    }
    false
}

// TODO: this isnt used or exported. Is this a viable fingerprint?
#[allow(unused)]
pub(crate) fn spending_witness_has_uncompressed_pubkey(spending_tx: &Transaction) -> bool {
    for input in spending_tx.input.iter() {
        if input.witness.is_empty() {
            return false;
        }
        for wit in input.witness.iter() {
            // Check if witness item is a pubkey
            match PublicKey::from_slice(wit) {
                Ok(_) => {
                    // Check if witness item starts with '04' byte
                    if wit.starts_with(&[0x04]) {
                        return true;
                    }
                }
                Err(_) => {
                    continue;
                }
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::TxOutWithOutpoint;
    use bitcoin::{ScriptBuf, TxIn, TxOut};
    use std::str::FromStr;
    // TODO: need a test harness/util for creating transactions and prevouts

    fn create_p2pk_script(compressed: bool) -> ScriptBuf {
        // Create a public key (compressed or uncompressed)
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();
        let (secret_key, _) = secp.generate_keypair(&mut rng);
        let pubkey = PublicKey::new(secret_key.public_key(&secp));

        // Force uncompressed if needed
        let pubkey_bytes = if compressed {
            pubkey.to_bytes()
        } else {
            // Create uncompressed pubkey (starts with 0x04)
            let mut uncompressed = vec![];
            uncompressed.extend_from_slice(&pubkey.inner.serialize_uncompressed());
            PublicKey::from_slice(&uncompressed).unwrap().to_bytes()
        };

        let pubkey = PublicKey::from_slice(&pubkey_bytes).unwrap();
        assert_eq!(pubkey.compressed, compressed);
        let script = ScriptBuf::new_p2pk(&pubkey);
        script
    }

    #[test]
    fn test_spending_spk_has_uncompressed_pubkey_with_compressed_p2pk() {
        // Create a P2PK script with compressed pubkey
        let spk = create_p2pk_script(true);
        let outpoint = OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000:0",
        )
        .unwrap();

        let prev_out = TxOutWithOutpoint {
            txout: TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: spk,
            },
            outpoint,
        };

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };

        let result = spending_spk_has_uncompressed_pubkey(&spending_tx, &[prev_out]);
        assert_eq!(result, false, "false for compressed pubkey");
    }

    #[test]
    fn test_spending_spk_has_uncompressed_pubkey_with_uncompressed_p2pk() {
        // Create a P2PK script with uncompressed pubkey
        let spk = create_p2pk_script(false);
        let outpoint = OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000:0",
        )
        .unwrap();

        let prev_out = TxOutWithOutpoint {
            txout: TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: spk,
            },
            outpoint,
        };

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };

        let result = spending_spk_has_uncompressed_pubkey(&spending_tx, &[prev_out]);
        assert_eq!(result, true, "true for uncompressed pubkey");
    }

    #[test]
    fn test_spending_spk_has_uncompressed_pubkey_with_non_p2pk() {
        let address = bitcoin::Address::from_str("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa")
            .unwrap()
            .require_network(bitcoin::Network::Bitcoin)
            .unwrap();
        let spk = address.script_pubkey();
        let outpoint = OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000:0",
        )
        .unwrap();

        let prev_out = TxOutWithOutpoint {
            txout: TxOut {
                value: bitcoin::Amount::from_sat(1000),
                script_pubkey: spk,
            },
            outpoint,
        };

        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                script_sig: ScriptBuf::new(),
                sequence: bitcoin::Sequence::MAX,
                witness: bitcoin::Witness::new(),
            }],
            output: vec![],
        };

        let result = spending_spk_has_uncompressed_pubkey(&spending_tx, &[prev_out]);
        assert_eq!(result, false, "Should return false for non-P2PK scripts");
    }

    #[test]
    fn test_spending_spk_has_uncompressed_pubkey_with_multiple_inputs() {
        let spk1 = create_p2pk_script(true); // compressed
        let spk2 = create_p2pk_script(false); // uncompressed

        let outpoint1 = OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000001:0",
        )
        .unwrap();
        let outpoint2 = OutPoint::from_str(
            "0000000000000000000000000000000000000000000000000000000000000002:0",
        )
        .unwrap();

        let prev_outs = vec![
            TxOutWithOutpoint {
                txout: TxOut {
                    value: bitcoin::Amount::from_sat(1000),
                    script_pubkey: spk1,
                },
                outpoint: outpoint1,
            },
            TxOutWithOutpoint {
                txout: TxOut {
                    value: bitcoin::Amount::from_sat(2000),
                    script_pubkey: spk2,
                },
                outpoint: outpoint2,
            },
        ];

        // Spending tx with first input being compressed P2PK
        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![
                TxIn {
                    previous_output: outpoint1,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
                TxIn {
                    previous_output: outpoint2,
                    script_sig: ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                },
            ],
            output: vec![],
        };

        // Should return true because first input has compressed P2PK
        let result = spending_spk_has_uncompressed_pubkey(&spending_tx, &prev_outs);
        assert_eq!(result, true, "true when first input has compressed P2PK");
    }

    #[test]
    fn test_spending_spk_has_uncompressed_pubkey_with_empty_inputs() {
        let spending_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: bitcoin::locktime::absolute::LockTime::ZERO,
            input: vec![],
            output: vec![],
        };

        let result = spending_spk_has_uncompressed_pubkey(&spending_tx, &[]);
        assert_eq!(result, false, "false for empty inputs");
    }
}
