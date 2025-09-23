use std::collections::HashSet;

use bitcoin::{ecdsa::Signature as EcdsaSignature, Amount, OutPoint, Transaction};

use crate::{util::{extract_all_signatures, OutputType}, TxOutWithOutpoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InputWithAmount {
    amount: Amount,
    outpoint: OutPoint,
}

/// Returns the input sorting types detected in the transaction
pub(crate) fn get_input_order(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> Vec<InputSortingType> {
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
pub(crate) enum InputSortingType {
    Single,
    Ascending,
    Descending,
    Bip69,
    // TODO: current unused. If we have confirmation height on input, we can use this
    Historical,
    Unknown,
}

pub(crate) fn get_input_types(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> Vec<OutputType> {
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