//! This module contains functions for detecting a wallet given a Bitcoin transaction.
//! This is a port of Python code from here: https://github.com/ishaanam/wallet-fingerprinting/blob/master/fingerprinting.py

mod util;

use bitcoin::secp256k1::PublicKey;
use bitcoin::transaction::Version;
use bitcoin::{
    ecdsa::Signature as EcdsaSignature, Address, AddressType, Amount, Network, OutPoint, Sequence,
    Transaction, TxOut,
};
use std::collections::HashSet;
use util::extract_all_signatures;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputSortingType {
    Single,
    Ascending,
    Descending,
    Bip69,
    Historical,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStructureType {
    Single,
    Double,
    Multi,
    ChangeLast,
    Bip69,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WalletType {
    BitcoinCore,
    Electrum,
    BlueWallet,
    Coinbase,
    Exodus,
    Trust,
    Trezor,
    Ledger,
    Unclear,
    Other,
}

impl WalletType {
    pub fn as_str(&self) -> &'static str {
        match self {
            WalletType::BitcoinCore => "Bitcoin Core",
            WalletType::Electrum => "Electrum",
            WalletType::BlueWallet => "Blue Wallet",
            WalletType::Coinbase => "Coinbase Wallet",
            WalletType::Exodus => "Exodus Wallet",
            WalletType::Trust => "Trust Wallet",
            WalletType::Trezor => "Trezor",
            WalletType::Ledger => "Ledger",
            WalletType::Unclear => "Unclear",
            WalletType::Other => "Other",
        }
    }
}

#[derive(Debug)]
pub struct Heuristics {
    pub tx_version: i32,
    pub anti_fee_snipe: bool,
    pub low_r_grinding: f32,
    pub prob_bip69: Option<f64>,
    pub mixed_input_types: bool,
    pub maybe_same_change_type: Option<bool>,
    pub input_types: HashSet<AddressType>,
}

pub fn using_uncompressed_pubkeys(
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct InputWithAmount {
    amount: Amount,
    outpoint: OutPoint,
}

/// Returns the input sorting types detected in the transaction
pub fn get_input_order(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> Vec<InputSortingType> {
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
pub fn low_order_r_grinding(tx: &Transaction) -> bool {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InputType {
    Opreturn,
    Nulldata,
    Address(AddressType),
}

fn get_type(prevout: &TxOut) -> InputType {
    let address =
        Address::from_script(&prevout.script_pubkey, Network::Bitcoin).expect("Always valid types");
    if let Some(address_type) = address.address_type() {
        return InputType::Address(address_type);
    } else {
        if prevout.script_pubkey.is_op_return() {
            return InputType::Opreturn;
        } else {
            return InputType::Nulldata;
        }
    }
}

pub fn get_input_types(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> Vec<InputType> {
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

pub fn get_output_types(tx: &Transaction) -> Vec<InputType> {
    let mut output_types = Vec::new();
    for output in tx.output.iter() {
        output_types.push(get_type(output));
    }
    output_types
}

/// Returns true if the transaction has mixed input types
pub fn mixed_input_types(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> bool {
    let input_types = get_input_types(tx, prev_outs)
        .into_iter()
        .collect::<HashSet<InputType>>();
    input_types.len() > 1
}

/// Returns true if the transaction appears to use anti-fee sniping
/// by setting locktime close to current block height
pub fn is_anti_fee_sniping(tx: &Transaction) -> bool {
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

/// TxOut with OutPoint of the tx input spending the output
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxOutWithOutpoint {
    txout: TxOut,
    outpoint: OutPoint,
}

impl TxOutWithOutpoint {
    fn get_type(&self) -> InputType {
        get_type(&self.txout)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeIndex {
    NoChange,     // Single output tx (-1)
    Inconclusive, // Could not determine (-2)
    Found(usize), // Index of change output
}

impl ChangeIndex {
    pub fn index(&self) -> Option<usize> {
        match self {
            ChangeIndex::NoChange => None,
            ChangeIndex::Inconclusive => None,
            ChangeIndex::Found(index) => Some(*index),
        }
    }
}
/// Attempts to identify the change output in a transaction using various heuristics
pub fn get_change_index(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> ChangeIndex {
    // Single output case
    if tx.output.len() == 1 {
        return ChangeIndex::NoChange;
    }

    // Get input address types
    let input_types = get_input_types(tx, prev_outs);
    // Get output address types
    let output_types = get_output_types(tx);

    // Check if all inputs are same type and exactly one output matches
    if input_types.iter().all(|t| *t == input_types[0]) {
        let matching = output_types
            .iter()
            .enumerate()
            .filter(|(_, t)| **t == input_types[0])
            .map(|(i, _)| i)
            .collect::<Vec<_>>();

        if matching.len() == 1 {
            return ChangeIndex::Found(matching[0]);
        }
    }

    // Check for address reuse
    let input_scripts: HashSet<_> = prev_outs
        .iter()
        .map(|txout| txout.txout.script_pubkey.clone())
        .collect();

    let shared_scripts: Vec<_> = tx
        .output
        .iter()
        .map(|txout| txout.script_pubkey.clone())
        .filter(|script| input_scripts.contains(script))
        .collect();

    if shared_scripts.len() == 1 {
        if let Some(idx) = tx
            .output
            .iter()
            .position(|txout| txout.script_pubkey == shared_scripts[0])
        {
            return ChangeIndex::Found(idx);
        }
    }

    // Check for non-round amounts
    let possible_indices: Vec<_> = tx
        .output
        .iter()
        .enumerate()
        .filter(|(_, txout)| txout.value.to_sat() % 100 != 0)
        .map(|(i, _)| i)
        .collect();

    if possible_indices.len() == 1 {
        return ChangeIndex::Found(possible_indices[0]);
    }

    ChangeIndex::Inconclusive
}

pub enum ChangeTypeMatchedInputs {
    NoChangeOrInconclusive,
    ChangeMatchesInputsTypes,
    ChangeMatchesOutputsTypes,
    MatchesInputsAndOutputs,
    NoMatchesInputsOrOutputs,
}

pub fn change_type_matched_inputs(
    tx: &Transaction,
    prev_outs: &[TxOutWithOutpoint],
) -> ChangeTypeMatchedInputs {
    let change_index = get_change_index(tx, prev_outs);

    if matches!(
        change_index,
        ChangeIndex::NoChange | ChangeIndex::Inconclusive
    ) {
        return ChangeTypeMatchedInputs::NoChangeOrInconclusive;
    }

    let change_type = get_type(&tx.output[change_index.index().expect("Checked above")]);
    let input_types = get_input_types(tx, prev_outs);
    // Remove the change output from the txouts
    let mut tx = tx.clone();
    tx.output
        .remove(change_index.index().expect("Checked above"));
    let output_types = get_output_types(&tx);

    let matches_input_types = input_types.iter().all(|t| *t == change_type);
    let matches_output_types = output_types.iter().all(|t| *t == change_type);

    if matches_input_types && matches_output_types {
        return ChangeTypeMatchedInputs::MatchesInputsAndOutputs;
    }
    if matches_input_types {
        return ChangeTypeMatchedInputs::ChangeMatchesInputsTypes;
    }
    if matches_output_types {
        return ChangeTypeMatchedInputs::ChangeMatchesOutputsTypes;
    }

    ChangeTypeMatchedInputs::NoMatchesInputsOrOutputs
}

/// Returns the output structure types detected in the transaction
pub fn get_output_structure(
    tx: &Transaction,
    prev_outs: &[TxOutWithOutpoint],
) -> Vec<OutputStructureType> {
    let mut output_structure = Vec::new();

    // Single output case
    if tx.output.len() == 1 {
        return vec![OutputStructureType::Single];
    }

    // Double or Multi output case
    if tx.output.len() == 2 {
        output_structure.push(OutputStructureType::Double);
    } else {
        output_structure.push(OutputStructureType::Multi);
    }

    // Check if change output is last
    if let ChangeIndex::Found(idx) = get_change_index(tx, prev_outs) {
        if idx == tx.output.len() - 1 {
            output_structure.push(OutputStructureType::ChangeLast);
        }
    }

    let amounts: Vec<_> = tx.output.iter().map(|out| out.value).collect();

    // Check if amounts are unique
    let unique_amounts: HashSet<_> = amounts.iter().collect();

    if unique_amounts.len() != amounts.len() {
        // Duplicate amounts - check both amounts and scripts are sorted
        let mut sorted_outputs = tx.output.clone();
        sorted_outputs.sort_by(|a, b| {
            a.value
                .cmp(&b.value)
                .then_with(|| a.script_pubkey.cmp(&b.script_pubkey))
        });

        if tx
            .output
            .iter()
            .zip(sorted_outputs.iter())
            .all(|(a, b)| a.value == b.value && a.script_pubkey == b.script_pubkey)
        {
            output_structure.push(OutputStructureType::Bip69);
        }
    } else {
        // Unique amounts - just check amounts are sorted
        if amounts.windows(2).all(|w| w[0] <= w[1]) {
            output_structure.push(OutputStructureType::Bip69);
        }
    }

    output_structure
}

/// Returns true if the transaction signals RBF (Replace-By-Fee)
/// by having at least one input with sequence number less than 0xffffffff
pub fn signals_rbf(tx: &Transaction) -> bool {
    tx.input.iter().any(|input| input.sequence < Sequence::MAX)
}

/// Returns true if any output address matches any input address, indicating address reuse
pub fn address_reuse(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> bool {
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

/// Attempt to detect the wallet type of a transaction
/// Given the transaction and the previous transactions which are the inputs to the current transaction
pub fn detect_wallet(
    tx: &Transaction,
    prev_txs: &[Transaction],
) -> (HashSet<WalletType>, Vec<String>) {
    // TODO do some validation on the previous transactions
    let prev_txouts = tx
        .input
        .iter()
        .map(|txin| TxOutWithOutpoint {
            txout: prev_txs
                .iter()
                .find(|prev_tx| prev_tx.compute_txid() == txin.previous_output.txid)
                .unwrap()
                .output[txin.previous_output.vout as usize]
                .clone(),
            outpoint: txin.previous_output,
        })
        .collect::<Vec<_>>();

    // Sanity checks
    assert!(prev_txouts.len() == tx.input.len());
    // assert outpoints match
    for (prev_txout, txin) in prev_txouts.iter().zip(tx.input.iter()) {
        assert_eq!(prev_txout.outpoint, txin.previous_output);
    }

    println!("prev_txouts: {:?}", prev_txouts);

    let mut possible_wallets = HashSet::from([
        WalletType::BitcoinCore,
        WalletType::Electrum,
        WalletType::BlueWallet,
        WalletType::Coinbase,
        WalletType::Exodus,
        WalletType::Trust,
        WalletType::Trezor,
        WalletType::Ledger,
    ]);
    let mut reasoning = Vec::new();

    // Anti-fee-sniping
    if is_anti_fee_sniping(tx) {
        reasoning.push("Anti-fee-sniping".to_string());
        possible_wallets.retain(|w| *w == WalletType::BitcoinCore || *w == WalletType::Electrum);
    } else {
        reasoning.push("No Anti-fee-sniping".to_string());
        possible_wallets.remove(&WalletType::BitcoinCore);
        possible_wallets.remove(&WalletType::Electrum);
    }

    // Uncompressed public keys
    if !using_uncompressed_pubkeys(tx, &prev_txouts) {
        reasoning.push("Uncompressed public key(s)".to_string());
        possible_wallets.clear();
        // Can we short-circuit here?
    } else {
        reasoning.push("All compressed public keys".to_string());
    }

    // Transaction version
    match tx.version {
        Version::ONE => {
            reasoning.push("nVersion = 1".to_string());
            possible_wallets.remove(&WalletType::BitcoinCore);
            possible_wallets.remove(&WalletType::Electrum);
            possible_wallets.remove(&WalletType::BlueWallet);
            possible_wallets.remove(&WalletType::Exodus);
            possible_wallets.remove(&WalletType::Coinbase);
        }
        Version::TWO => {
            reasoning.push("nVersion = 2".to_string());
            possible_wallets.remove(&WalletType::Ledger);
            possible_wallets.remove(&WalletType::Trezor);
            possible_wallets.remove(&WalletType::Trust);
        }
        _ => {
            reasoning.push("non-standard nVersion number".to_string());
            possible_wallets.clear();
        }
    }

    // Low-r signatures
    if !low_order_r_grinding(tx) {
        reasoning.push("Not low-r-grinding".to_string());
        possible_wallets.remove(&WalletType::BitcoinCore);
        possible_wallets.remove(&WalletType::Electrum);
    } else {
        reasoning.push("Low r signatures only".to_string());
    }

    // RBF
    if signals_rbf(tx) {
        reasoning.push("signals RBF".to_string());
        possible_wallets.remove(&WalletType::Coinbase);
        possible_wallets.remove(&WalletType::Exodus);
    } else {
        reasoning.push("does not signal RBF".to_string());
        possible_wallets.remove(&WalletType::BitcoinCore);
        possible_wallets.remove(&WalletType::Electrum);
        possible_wallets.remove(&WalletType::BlueWallet);
        possible_wallets.remove(&WalletType::Ledger);
        possible_wallets.remove(&WalletType::Trezor);
        possible_wallets.remove(&WalletType::Trust);
    }

    let input_types = get_input_types(tx, &prev_txouts);
    if input_types
        .iter()
        // Should differenciate between P2tr key and script spend
        .any(|t| *t == InputType::Address(AddressType::P2tr))
    {
        reasoning.push("Sends to taproot address".to_string());
        possible_wallets.remove(&WalletType::Coinbase);
    }
    if input_types
        .iter()
        .any(|t| *t == InputType::Opreturn || *t == InputType::Nulldata)
    {
        reasoning.push("Creates OP_RETURN output".to_string());
        possible_wallets.remove(&WalletType::Coinbase);
        possible_wallets.remove(&WalletType::Exodus);
        possible_wallets.remove(&WalletType::BlueWallet);
        possible_wallets.remove(&WalletType::Ledger);
        possible_wallets.remove(&WalletType::Trust);
    }

    // get output types
    let output_types = get_output_types(tx);
    if output_types
        .iter()
        .any(|t| t == &InputType::Address(AddressType::P2tr))
    {
        reasoning.push("Spends taproot output".to_string());
        possible_wallets.remove(&WalletType::Coinbase);
        possible_wallets.remove(&WalletType::Exodus);
        possible_wallets.remove(&WalletType::Electrum);
        possible_wallets.remove(&WalletType::BlueWallet);
        possible_wallets.remove(&WalletType::Ledger);
        possible_wallets.remove(&WalletType::Trust);
    }
    if output_types
        .iter()
        .any(|t| t == &InputType::Address(AddressType::P2wsh))
    {
        possible_wallets.remove(&WalletType::Coinbase);
        possible_wallets.remove(&WalletType::Exodus);
        possible_wallets.remove(&WalletType::Trust);
        possible_wallets.remove(&WalletType::Trezor);
    }
    if output_types
        .iter()
        .any(|t| t == &InputType::Address(AddressType::P2pkh))
    {
        reasoning.push("Spends P2PKH output".to_string());
        possible_wallets.remove(&WalletType::Exodus);
        possible_wallets.remove(&WalletType::Trust);
    }

    // Multi-type vin
    if mixed_input_types(tx, &prev_txouts) {
        reasoning.push("Has multi-type vin".to_string());
        possible_wallets.remove(&WalletType::Exodus);
        possible_wallets.remove(&WalletType::Electrum);
        possible_wallets.remove(&WalletType::BlueWallet);
        possible_wallets.remove(&WalletType::Ledger);
        possible_wallets.remove(&WalletType::Trezor);
        possible_wallets.remove(&WalletType::Trust);
    }

    // Change type matched inputs/outputs
    let change_matched_inputs = change_type_matched_inputs(tx, &prev_txouts);
    if matches!(
        change_matched_inputs,
        ChangeTypeMatchedInputs::ChangeMatchesOutputsTypes
    ) {
        reasoning.push("Change type matched outputs".to_string());
        if possible_wallets.contains(&WalletType::BitcoinCore) {
            possible_wallets = HashSet::from([WalletType::BitcoinCore]);
        } else {
            possible_wallets.clear();
        }
    } else if matches!(
        change_matched_inputs,
        ChangeTypeMatchedInputs::ChangeMatchesInputsTypes
    ) {
        reasoning.push("Change type matched inputs".to_string());
        possible_wallets.remove(&WalletType::BitcoinCore);
    }

    // Address reuse
    if address_reuse(tx, &prev_txouts) {
        reasoning.push("Address reuse between vin and vout".to_string());
        possible_wallets.remove(&WalletType::Coinbase);
        possible_wallets.remove(&WalletType::BitcoinCore);
        possible_wallets.remove(&WalletType::Electrum);
        possible_wallets.remove(&WalletType::BlueWallet);
        possible_wallets.remove(&WalletType::Ledger);
        possible_wallets.remove(&WalletType::Trezor);
    } else {
        reasoning.push("No address reuse between vin and vout".to_string());
        possible_wallets.remove(&WalletType::Exodus);
        possible_wallets.remove(&WalletType::Trust);
    }

    // Input/output structure
    let input_order = get_input_order(tx, &prev_txouts);
    println!("input_order: {:?}", input_order);
    let output_structure = get_output_structure(tx, &prev_txouts);

    // if output_structure.contains(&OutputStructureType::Multi) {
    //     reasoning.push("More than 2 outputs".to_string());
    //     possible_wallets.remove(&WalletType::Coinbase);
    //     possible_wallets.remove(&WalletType::Exodus);
    //     possible_wallets.remove(&WalletType::Ledger);
    //     possible_wallets.remove(&WalletType::Trust);
    // }

    // if !output_structure.contains(&OutputStructureType::Bip69) {
    //     reasoning.push("BIP-69 not followed by outputs".to_string());
    //     possible_wallets.remove(&WalletType::Electrum);
    //     possible_wallets.remove(&WalletType::Trezor);
    // } else {
    //     reasoning.push("BIP-69 followed by outputs".to_string());
    // }

    if !input_order.contains(&InputSortingType::Single) {
        if !input_order.contains(&InputSortingType::Bip69) {
            reasoning.push("BIP-69 not followed by inputs".to_string());
            possible_wallets.remove(&WalletType::Electrum);
            possible_wallets.remove(&WalletType::Trezor);
        } else {
            reasoning.push("BIP-69 followed by inputs".to_string());
        }
        if !input_order.contains(&InputSortingType::Historical) {
            reasoning.push("Inputs not ordered historically".to_string());
            possible_wallets.remove(&WalletType::Ledger);
        } else {
            reasoning.push("Inputs ordered historically".to_string());
        }
    }

    // Change index
    let change_index = get_change_index(tx, &prev_txouts);
    if let ChangeIndex::Found(idx) = change_index {
        if idx != tx.output.len() - 1 {
            reasoning.push("Last index is not change".to_string());
            possible_wallets.remove(&WalletType::Ledger);
            possible_wallets.remove(&WalletType::BlueWallet);
            possible_wallets.remove(&WalletType::Coinbase);
        } else {
            reasoning.push("Last index is change".to_string());
        }
    }

    if possible_wallets.is_empty() {
        return (HashSet::from([WalletType::Other]), reasoning);
    }

    (possible_wallets, reasoning)
}

#[cfg(test)]
mod tests {
    use bitcoin::consensus::Decodable;
    use hex;

    use super::*;

    fn get_tx_from_hex(hex: &str) -> Transaction {
        let reader = hex::decode(hex).unwrap();
        Transaction::consensus_decode(&mut reader.as_slice()).unwrap()
    }

    // Test vectors
    #[test]
    fn test_detect_wallet() {
        // Electrum Transaction
        let tx = get_tx_from_hex("02000000000102ac5718a0e7b3ee13ce2f273aa9c6a04becf8a1696edb75d3217c0d3790a620860000000000fdffffff74e1d8045cfe6b823943db609ceb3aa13216a936a9e18b92e26db770a8e4eae60000000000fdffffff02f6250000000000001600145333aa7bcef7bd632edaf5a326d4c6085417282d133f0000000000001976a914c8f57d6b8bc08fa211c71b8d255e7c4b25bd432288ac02473044022037059673792d5af9ab1cf5fc8ccf3c1c1ad300e9e6c25edda7a172e455d49e07022046d2c2638c129a8c9a54ca5adb5df01bde564066c36edade43c3845b3d25940101210202ca6c82b9cc52f7a8c34de6a6ccd807d8437a8368ddf7638a2b50002e745b360247304402207b3d3c39ee66bdaa509094072ae629794bd7ef0f14694f0e3695d89ed573c57202205cc9b6d059500ccf621621a657115e33c51064efad2dcf352ad32c69b0ae6ab301210202ca6c82b9cc52f7a8c34de6a6ccd807d8437a8368ddf7638a2b50002e745b3670360c00");

        println!(
            "{:?}",
            tx.input
                .iter()
                .map(|i| i.previous_output)
                .collect::<Vec<_>>()
        );
        let prev_txs = [
            get_tx_from_hex("01000000000101b6d971c9ca363c5f901780d578bd0449d74b80bb565f367d56278c3b1601f94301000000000000000001f41400000000000016001460ac2a83f14bdc2016edf615138aabdd52d6c331024730440220560c4bdf1acc416517bd9d50ef65f0a99ac1633a5b1a7a3cb69ee486ed688a3a022079db25e85e6b34690456ad49f952302a80e1c146a7bc7af5387e92c2d4277c7a01210281bfdda07273f79522c04bff9e43c03655ebf96e482c8f3e262ccb5551c969f200000000"),
            get_tx_from_hex("02000000000101b6d971c9ca363c5f901780d578bd0449d74b80bb565f367d56278c3b1601f9430000000000fdffffff019e5700000000000016001460ac2a83f14bdc2016edf615138aabdd52d6c331014079a93a95b32520c99a08cfae6f1dfca31242359ca42ba56873cf2be60f472ea330ab7273753602fa362ce106287b365bae5542cb7358157641d8e2a7a052245400000000")
        ];

        let (wallets, reasoning) = detect_wallet(&tx, &prev_txs);
        println!("{:?}", wallets);
        println!("{:?}", reasoning);
    }
}
