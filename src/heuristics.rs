use bitcoin::transaction::Version;

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
#[cfg_attr(feature = "ffi", derive(uniffi::Object))]
pub struct Heuristics {
    /* Global heuristics */
    /// The version of the transaction
    pub tx_version: Version,
    /// Whether the transaction protects against fee sniping attacks
    /// https://bitcoinops.org/en/topics/fee-sniping/
    pub anti_fee_snipe: bool,
    // TODO: should this be a f32 probability?
    /// Whether the transaction has any signatures with low order R values
    /// https://bitcoinops.org/en/topics/low-r-grinding/
    pub low_r_grinding: bool,
    /// Whether the transaction has outputs that are the same as any inputs
    pub address_reuse: bool,
    /// Whether the transaction has inputs or outputs that are the same "type" as the change output
    pub maybe_same_change_type: ChangeTypeMatchedInputs,
    /* Input heuristics */
    /// Whether the transaction has inputs that are of different "types"
    pub mixed_input_types: bool,
    /// The types of the inputs
    pub input_types: Vec<OutputType>,
    /// Whether the transaction has inputs that are using uncompressed public keys
    pub uncompressed_pubkeys: bool,
    /// Whether the transaction has inputs that are signals of RBF via BIP 125 (Replace-by-Fee)
    pub signals_rbf: bool,
    /// The ordering of the inputs
    pub input_order: Vec<InputSortingType>,
    /* Output heuristics */
    /// The types of the outputs
    pub output_types: Vec<OutputType>,
    /// The structure of the outputs
    pub output_structure: Vec<OutputStructureType>,
    /// The index of the change output
    pub change_index: ChangeIndex,
}

#[cfg(feature = "uniffi")]
#[uniffi::export]
impl Heuristics {
    #[cfg(feature = "uniffi")]
    #[uniffi::constructor]
    pub fn new(
        tx: std::sync::Arc<bitcoin_ffi::Transaction>,
        prev_txs: Vec<std::sync::Arc<bitcoin_ffi::Transaction>>,
    ) -> Self {
        // TODO do some validation on the previous transactions
        let prev_txouts = tx
            .0
            .input
            .iter()
            .map(|txin| TxOutWithOutpoint {
                txout: prev_txs
                    .iter()
                    .find(|prev_tx| prev_tx.compute_txid() == txin.previous_output.txid.to_string())
                    .unwrap()
                    .0
                    .output[txin.previous_output.vout as usize]
                    .clone(),
                outpoint: txin.previous_output,
            })
            .collect::<Vec<_>>();

        Self {
            tx_version: tx.0.version,
            anti_fee_snipe: is_anti_fee_sniping(&tx.0),
            low_r_grinding: low_order_r_grinding(&tx.0),
            mixed_input_types: mixed_input_types(&tx.0, &prev_txouts),
            maybe_same_change_type: change_type_matched_inputs(&tx.0, &prev_txouts),
            input_types: get_input_types(&tx.0, &prev_txouts),
            output_types: get_output_types(&tx.0),
            uncompressed_pubkeys: using_uncompressed_pubkeys(&tx.0, &prev_txouts),
            signals_rbf: signals_rbf(&tx.0),
            address_reuse: address_reuse(&tx.0, &prev_txouts),
            output_structure: get_output_structure(&tx.0, &prev_txouts),
            change_index: get_change_index(&tx.0, &prev_txouts),
            input_order: get_input_order(&tx.0, &prev_txouts),
        }
    }
}

#[cfg(not(feature = "uniffi"))]
impl Heuristics {
    #[cfg(not(feature = "uniffi"))]
    pub fn new(tx: bitcoin::Transaction, prev_txs: Vec<bitcoin::Transaction>) -> Self {
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

        Self {
            tx_version: tx.version,
            anti_fee_snipe: is_anti_fee_sniping(&tx),
            low_r_grinding: low_order_r_grinding(&tx),
            mixed_input_types: mixed_input_types(&tx, &prev_txouts),
            maybe_same_change_type: change_type_matched_inputs(&tx, &prev_txouts),
            input_types: get_input_types(&tx, &prev_txouts),
            output_types: get_output_types(&tx),
            uncompressed_pubkeys: using_uncompressed_pubkeys(&tx, &prev_txouts),
            signals_rbf: signals_rbf(&tx),
            address_reuse: address_reuse(&tx, &prev_txouts),
            output_structure: get_output_structure(&tx, &prev_txouts),
            change_index: get_change_index(&tx, &prev_txouts),
            input_order: get_input_order(&tx, &prev_txouts),
        }
    }
}
