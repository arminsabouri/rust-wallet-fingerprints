use std::collections::HashSet;

use bitcoin::Transaction;

use crate::util::TxOutWithOutpoint;

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

// TODO: move this to output.rs
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
