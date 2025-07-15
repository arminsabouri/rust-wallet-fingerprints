//! This module contains functions for detecting a wallet given a Bitcoin transaction.
//! This is a port of Python code from here: https://github.com/ishaanam/wallet-fingerprinting/blob/master/fingerprinting.py

mod util;

use bitcoin::secp256k1::ecdsa::Signature;
use bitcoin::secp256k1::PublicKey;
use bitcoin::transaction::Version;
use bitcoin::{
    Address, AddressType, Amount, Network, OutPoint, Sequence, Transaction, TxOut
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

pub fn using_uncompressed_pubkeys(spending_tx: &Transaction, prev_txs: &[Transaction]) -> bool {
    for input in spending_tx.input.iter() {
        let prev_tx = &prev_txs
            .iter()
            .find(|tx| tx.compute_txid() == input.previous_output.txid)
            .unwrap();
        let prev_out = prev_tx.output[input.previous_output.vout as usize].clone();
        let spk = prev_out.script_pubkey;
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

// TODO
// pub fn get_input_order(tx: &Transaction, prev_outs: &[TxOut]) -> Vec<InputSortingType> {
//     if tx.input.len() == 1 {
//         return vec![InputSortingType::Single];
//     }

//     let mut sorting_types = Vec::new();
//     let mut amounts = Vec::new();

//     // Collect amounts and prevouts
//     for input in &tx.input {
//         let prevout = prev_outs[input.previous_output.vout as usize];
//         amounts.push(InputWithAmount {
//             amount: prevout.value,
//             outpoint: input.previous_output,
//         });
//     }

//     // Check if amounts are sorted (if we had amounts)
//     if !amounts.is_empty() {
//         let mut sorted_amounts = amounts.clone();
//         sorted_amounts.sort_by_key(|a| a.amount);
//         if amounts == sorted_amounts {
//             sorting_types.push(InputSortingType::Ascending);
//         }

//         sorted_amounts.reverse();
//         if amounts == sorted_amounts {
//             sorting_types.push(InputSortingType::Descending);
//         }
//     }

//     // Check BIP69 sorting
//     let mut sorted_prevouts = prevouts.clone();
//     sorted_prevouts.sort();
//     if prevouts == sorted_prevouts {
//         sorting_types.push(InputSortingType::Bip69);
//     }

//     // Note: Historical sorting would require access to confirmation height data
//     // which isn't available in the Transaction struct alone

//     if sorting_types.is_empty() {
//         sorting_types.push(InputSortingType::Unknown);
//     }

//     sorting_types
// }

pub fn low_order_r_grinding(tx: &Transaction) -> bool {
    let sigs = extract_all_signatures(tx);
    for sig_bytes in sigs.iter() {
        let sig = Signature::from_der(sig_bytes).unwrap();
        let compact = sig.serialize_compact();
        if compact[0] < 0x80 {
            return true;
        }
    }

    false
}

/// Returns true if the transaction has mixed input types
pub fn mixed_input_types(tx: &Transaction, prev_outs: &[TxOut]) -> bool {
    let mut input_types = HashSet::new();
    for input in tx.input.iter() {
        let prevout = prev_outs[input.previous_output.vout as usize].clone();
        if let Ok(address) = Address::from_script(&prevout.script_pubkey, Network::Bitcoin) {
            if let Some(address_type) = address.address_type() {
                input_types.insert(address_type);
            }
        }
    }

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeIndex {
    NoChange,     // Single output tx (-1)
    Inconclusive, // Could not determine (-2)
    Found(usize), // Index of change output
}

/// Attempts to identify the change output in a transaction using various heuristics
pub fn get_change_index(tx: &Transaction, prev_outs: &[TxOut]) -> ChangeIndex {
    // Single output case
    if tx.output.len() == 1 {
        return ChangeIndex::NoChange;
    }

    // Get input address types
    let mut input_types = Vec::new();
    for input in tx.input.iter() {
        let prevout = &prev_outs[input.previous_output.vout as usize];
        if let Ok(addr) = Address::from_script(&prevout.script_pubkey, Network::Bitcoin) {
            if let Some(addr_type) = addr.address_type() {
                input_types.push(addr_type);
            }
        }
    }

    // Get output address types
    let mut output_types = Vec::new();
    for output in tx.output.iter() {
        if let Ok(addr) = Address::from_script(&output.script_pubkey, Network::Bitcoin) {
            if let Some(addr_type) = addr.address_type() {
                output_types.push(addr_type);
            }
        }
    }

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
        .map(|txout| txout.script_pubkey.clone())
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

/// Returns the output structure types detected in the transaction
pub fn get_output_structure(tx: &Transaction) -> Vec<OutputStructureType> {
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
    if let ChangeIndex::Found(idx) = get_change_index(tx, &[]) {
        if idx == tx.output.len() - 1 {
            output_structure.push(OutputStructureType::ChangeLast);
        }
    }

    // Check BIP69 ordering
    let amounts: Vec<_> = tx.output.iter().map(|out| out.value).collect();
    let scripts: Vec<_> = tx
        .output
        .iter()
        .map(|out| out.script_pubkey.clone())
        .collect();

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
    tx.input
        .iter()
        .any(|input| input.sequence < Sequence::MAX)
}

/// Returns true if any output address matches any input address, indicating address reuse
pub fn address_reuse(tx: &Transaction, prev_outs: &[TxOut]) -> bool {
    // Get script pubkeys from inputs
    let input_scripts: HashSet<_> = prev_outs
        .iter()
        .map(|txout| txout.script_pubkey.clone())
        .collect();

    // Get script pubkeys from outputs
    let output_scripts: HashSet<_> = tx
        .output
        .iter()
        .map(|txout| txout.script_pubkey.clone())
        .collect();

    !input_scripts.is_disjoint(&output_scripts)
}

pub fn detect_wallet(tx: &Transaction) -> (HashSet<WalletType>, Vec<String>) {
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

    // Check anti-fee sniping
    match is_anti_fee_sniping(tx) {
        true => {
            reasoning.push("Anti-fee-sniping".to_string());
            possible_wallets
                .retain(|w| matches!(w, WalletType::BitcoinCore | WalletType::Electrum));
        }
        false => {
            reasoning.push("No Anti-fee-sniping".to_string());
            possible_wallets.remove(&WalletType::BitcoinCore);
            possible_wallets.remove(&WalletType::Electrum);
        }
    }

    // Check transaction version
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

    if possible_wallets.is_empty() {
        (HashSet::from([WalletType::Other]), reasoning)
    } else {
        (possible_wallets, reasoning)
    }
}
