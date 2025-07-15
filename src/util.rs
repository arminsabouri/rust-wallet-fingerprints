use bitcoin::blockdata::script::Instruction;
use bitcoin::{Script, Transaction};

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
        .filter(|data| {
            data.len() >= 9 && data[0] == 0x30 // DER-encoded signature likely
        })
        .map(|data| data.to_vec())
        .collect()
}

/// Extract all sigs from tx.inputs, picking scriptSig OR witness per input
pub fn extract_all_signatures(tx: &Transaction) -> Vec<Vec<u8>> {
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
