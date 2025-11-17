use std::collections::HashSet;

use bitcoin::Transaction;

use crate::{
    input::get_input_types,
    util::{get_output_type, OutputType, TxOutWithOutpoint},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeIndex {
    /// Single output tx
    NoChange,
    /// Could not determine
    Inconclusive,
    /// Index of change output
    Found(usize),
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
pub(crate) fn get_change_index(tx: &Transaction, prev_outs: &[TxOutWithOutpoint]) -> ChangeIndex {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]
pub enum ChangeTypeMatchedInputs {
    /// No change output or could not determine
    NoChangeOrInconclusive,
    /// Change output matches input types
    ChangeMatchesInputsTypes,
    /// Change output matches output types
    ChangeMatchesOutputsTypes,
    /// Change output matches both input and output types
    MatchesInputsAndOutputs,
    /// Change output does not match any input or output types
    NoMatchesInputsOrOutputs,
}

pub(crate) fn change_type_matched_inputs(
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

    let change_type = get_output_type(&tx.output[change_index.index().expect("Checked above")]);
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "ffi", derive(uniffi::Enum))]

pub enum OutputStructureType {
    /// Single output
    Single,
    /// Two outputs
    Double,
    /// More than two outputs
    Multi,
    /// Change output is the last output
    ChangeLast,
    /// Outputs are sorted according to BIP 69
    Bip69,
}

/// Returns the output structure types detected in the transaction
pub(crate) fn get_output_structure(
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

pub(crate) fn get_output_types(tx: &Transaction) -> Vec<OutputType> {
    let mut output_types = Vec::new();
    for output in tx.output.iter() {
        output_types.push(get_output_type(output));
    }
    output_types
}
