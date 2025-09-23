use bitcoin::{transaction::Version, Transaction};

use crate::{
    global::{address_reuse, is_anti_fee_sniping, signals_rbf, using_uncompressed_pubkeys},
    input::{
        get_input_order, get_input_types, low_order_r_grinding, mixed_input_types, InputSortingType,
    },
    output::{
        change_type_matched_inputs, get_change_index, get_output_structure, get_output_types,
        ChangeIndex, ChangeTypeMatchedInputs, OutputStructureType,
    },
    util::{OutputType, TxOutWithOutpoint},
};

#[derive(Debug)]
pub struct Heuristics {
    pub tx_version: Version,
    pub anti_fee_snipe: bool,
    // TODO: should this be a f32 probability?
    pub low_r_grinding: bool,
    pub mixed_input_types: bool,
    pub maybe_same_change_type: ChangeTypeMatchedInputs,
    pub input_types: Vec<OutputType>,
    pub output_types: Vec<OutputType>,
    pub uncompressed_pubkeys: bool,
    pub signals_rbf: bool,
    pub address_reuse: bool,
    pub output_structure: Vec<OutputStructureType>,
    pub change_index: ChangeIndex,
    pub input_order: Vec<InputSortingType>,
}

impl Heuristics {
    pub fn new(tx: &Transaction, prev_txs: &[Transaction]) -> Self {
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

        let input_types = get_input_types(tx, &prev_txouts);
        let output_types = get_output_types(tx);
        let change_index = get_change_index(tx, &prev_txouts);
        let output_structure = get_output_structure(tx, &prev_txouts);
        let address_reuse = address_reuse(tx, &prev_txouts);
        let anti_fee_snipe = is_anti_fee_sniping(tx);
        let low_r_grinding = low_order_r_grinding(tx);
        let mixed_input_types = mixed_input_types(tx, &prev_txouts);
        let same_change_type = change_type_matched_inputs(tx, &prev_txouts);
        let uncompressed_pubkeys = using_uncompressed_pubkeys(tx, &prev_txouts);
        let signals_rbf = signals_rbf(tx);
        let input_order = get_input_order(tx, &prev_txouts);

        Self {
            tx_version: tx.version,
            anti_fee_snipe,
            low_r_grinding,
            mixed_input_types,
            maybe_same_change_type: same_change_type,
            input_types,
            output_types,
            uncompressed_pubkeys,
            signals_rbf,
            address_reuse,
            output_structure,
            change_index,
            input_order,
        }
    }
}
