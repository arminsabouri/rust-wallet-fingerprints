use bitcoin::blockdata::script::Instruction;
use bitcoin::{ecdsa::Signature as EcdsaSignature, Script, Transaction};
use bitcoin::{Address, AddressType, Network, OutPoint, TxOut};

/// Extracts ECDSA signatures from a scriptSig
fn extract_signatures_from_scriptsig(script_sig: &Script) -> Vec<Vec<u8>> {
    script_sig
        .instructions()
        .filter_map(|instr| match instr {
            Ok(Instruction::PushBytes(bytes)) => Some(bytes.as_bytes().to_vec()),
            _ => None,
        })
        .filter(|data| {
            // Check if it’s a DER-encoded signature with sighash type
            data.len() >= 9 && data[0] == 0x30 // DER prefix
        })
        .collect()
}

/// Extracts ECDSA signatures from witness stack
fn extract_signatures_from_witness(witness: &bitcoin::Witness) -> Vec<Vec<u8>> {
    witness
        .iter()
        .filter(|data| EcdsaSignature::from_slice(data).is_ok())
        .map(|data| data.to_vec())
        .collect()
}

/// Extract all sigs from tx.inputs, picking scriptSig OR witness per input
pub(crate) fn extract_all_signatures(tx: &Transaction) -> Vec<Vec<u8>> {
    tx.input
        .iter()
        .flat_map(|txin| {
            if !txin.script_sig.is_empty() {
                extract_signatures_from_scriptsig(&txin.script_sig)
            } else if !txin.witness.is_empty() {
                extract_signatures_from_witness(&txin.witness)
            } else {
                vec![]
            }
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OutputType {
    Opreturn,
    NonStandard,
    Address(AddressType),
}

pub(crate) fn get_output_type(prevout: &TxOut) -> OutputType {
    let address =
        // FIXME: hardcoded network
        Address::from_script(&prevout.script_pubkey, Network::Bitcoin).expect("Always valid types");
    if let Some(address_type) = address.address_type() {
        return OutputType::Address(address_type);
    } else {
        if prevout.script_pubkey.is_op_return() {
            return OutputType::Opreturn;
        } else {
            return OutputType::NonStandard;
        }
    }
}

/// TxOut with OutPoint of the tx input spending the output
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct TxOutWithOutpoint {
    pub(crate) txout: TxOut,
    pub(crate) outpoint: OutPoint,
}

impl TxOutWithOutpoint {
    pub(crate) fn get_type(&self) -> OutputType {
        get_output_type(&self.txout)
    }
}
