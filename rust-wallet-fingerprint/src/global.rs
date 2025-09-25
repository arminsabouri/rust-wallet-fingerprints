use std::collections::HashSet;

use bitcoin::{PublicKey, Transaction};

use crate::util::TxOutWithOutpoint;

pub(crate) fn using_uncompressed_pubkeys(
    spending_tx: &Transaction,
    prev_outs: &[TxOutWithOutpoint],
) -> bool {
    for input in spending_tx.input.iter() {
        let prev_out = &prev_outs
            .iter()
            .find(|txout| txout.outpoint == input.previous_output)
            .expect("Previous transaction should always exist")
            .txout;
        let spk = prev_out.script_pubkey.clone();
        if spk.is_p2sh() || spk.is_p2wsh() || spk.is_p2tr() {
            return false;
        }
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
    true
}

/// Returns true if the transaction appears to use anti-fee sniping
/// by setting locktime close to current block height
pub(crate) fn is_anti_fee_sniping(tx: &Transaction) -> bool {
    // If locktime is 0, definitely not using anti-fee sniping
    if tx.lock_time.to_consensus_u32() == 0 {
        return false;
    }

    // Note: In a full implementation, we would check if:
    // current_height - locktime < 100
    // However we don't have access to current height in this context
    // So we just check if locktime is non-zero as a heuristic
    true
}

/// Returns true if the transaction signals RBF (Replace-By-Fee)
/// by having at least one input with sequence number less than 0xffffffff
pub(crate) fn signals_rbf(tx: &Transaction) -> bool {
    tx.input.iter().any(|input| input.sequence.is_rbf())
}

/// Returns true if any output address matches any input address, indicating address reuse
pub(crate) fn address_reuse(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> bool {
    // Get script pubkeys from inputs
    let input_scripts: HashSet<_> = prev_outs
        .iter()
        .map(|txout| txout.txout.script_pubkey.clone())
        .collect();

    // Get script pubkeys from outputs
    let output_scripts: HashSet<_> = tx
        .output
        .iter()
        .map(|txout| txout.script_pubkey.clone())
        .collect();

    !input_scripts.is_disjoint(&output_scripts)
}
