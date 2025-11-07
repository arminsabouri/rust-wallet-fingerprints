//! This module contains functions for detecting a wallet given a Bitcoin transaction.
//! This is a port of Python code from here: https://github.com/ishaanam/wallet-fingerprinting/blob/master/fingerprinting.py

mod global;
pub mod heuristics;
mod input;
mod output;
mod util;

use bitcoin::transaction::Version;
use bitcoin::{AddressType, Transaction};
use std::collections::HashSet;

uniffi::setup_scaffolding!();


use crate::global::{address_reuse, signals_rbf, using_uncompressed_pubkeys};
use crate::input::{
    get_input_order, get_input_types, low_order_r_grinding, mixed_input_types, InputSortingType,
};
use crate::output::{
    change_type_matched_inputs, get_change_index, get_output_structure, get_output_types,
    ChangeIndex, ChangeTypeMatchedInputs, OutputStructureType,
};
use crate::util::OutputType;
use crate::{global::is_anti_fee_sniping, util::TxOutWithOutpoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum WalletType {
    BitcoinCore,
    Electrum,
    BlueWallet,
    Coinbase,
    Exodus,
    Trust,
    Trezor,
    Ledger,
    #[allow(unused)]
    Unclear,
    Other,
}

/// Attempt to detect the wallet type of a transaction
/// Given the transaction and the previous transactions which are the inputs to the current transaction
/// TODO: this method is was ported from the python impl and is most likely not up to date
#[allow(unused)]
fn detect_wallet(tx: &Transaction, prev_txs: &[Transaction]) -> (HashSet<WalletType>, Vec<String>) {
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
        return (possible_wallets, reasoning);
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
        // TODO: Should differenciate between P2tr key and script spend
        .any(|t| *t == OutputType::Address(AddressType::P2tr))
    {
        reasoning.push("Sends to taproot address".to_string());
        possible_wallets.remove(&WalletType::Coinbase);
    }
    if input_types
        .iter()
        .any(|t| *t == OutputType::Opreturn || *t == OutputType::NonStandard)
    {
        reasoning.push("Creates OP_RETURN output".to_string());
        possible_wallets.remove(&WalletType::Coinbase);
        possible_wallets.remove(&WalletType::Exodus);
        possible_wallets.remove(&WalletType::BlueWallet);
        possible_wallets.remove(&WalletType::Ledger);
        possible_wallets.remove(&WalletType::Trust);
    }

    // get output types
    // TODO: these output types are super outdate now
    let output_types = get_output_types(tx);
    if output_types
        .iter()
        .any(|t| t == &OutputType::Address(AddressType::P2tr))
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
        .any(|t| t == &OutputType::Address(AddressType::P2wsh))
    {
        possible_wallets.remove(&WalletType::Coinbase);
        possible_wallets.remove(&WalletType::Exodus);
        possible_wallets.remove(&WalletType::Trust);
        possible_wallets.remove(&WalletType::Trezor);
    }
    if output_types
        .iter()
        .any(|t| t == &OutputType::Address(AddressType::P2pkh))
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

    if output_structure.contains(&OutputStructureType::Multi) {
        reasoning.push("More than 2 outputs".to_string());
        possible_wallets.remove(&WalletType::Coinbase);
        possible_wallets.remove(&WalletType::Exodus);
        possible_wallets.remove(&WalletType::Ledger);
        possible_wallets.remove(&WalletType::Trust);
    }

    if !output_structure.contains(&OutputStructureType::Bip69) {
        reasoning.push("BIP-69 not followed by outputs".to_string());
        possible_wallets.remove(&WalletType::Electrum);
        possible_wallets.remove(&WalletType::Trezor);
    } else {
        reasoning.push("BIP-69 followed by outputs".to_string());
    }

    if !input_order.contains(&InputSortingType::Single) {
        if !input_order.contains(&InputSortingType::Bip69) {
            reasoning.push("BIP-69 not followed by inputs".to_string());
            possible_wallets.remove(&WalletType::Electrum);
            possible_wallets.remove(&WalletType::Trezor);
        } else {
            reasoning.push("BIP-69 followed by inputs".to_string());
        }
        // TODO: historical input sorting not supported until we can have # of confirmations passed in
        // if !input_order.contains(&InputSortingType::Historical) {
        //     reasoning.push("Inputs not ordered historically".to_string());
        //     possible_wallets.remove(&WalletType::Ledger);
        // } else {
        //     reasoning.push("Inputs ordered historically".to_string());
        // }
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
        struct TestVector {
            tx: Transaction,
            prev_txs: Vec<Transaction>,
            expected_wallets: HashSet<WalletType>,
        }
        let test_vectors = vec![
        // Elecrum: 5d857401648a667303cde43295bce1326e6329353eac3dddf15b151e701405e7    
        TestVector {
            tx: get_tx_from_hex("02000000000102ac5718a0e7b3ee13ce2f273aa9c6a04becf8a1696edb75d3217c0d3790a620860000000000fdffffff74e1d8045cfe6b823943db609ceb3aa13216a936a9e18b92e26db770a8e4eae60000000000fdffffff02f6250000000000001600145333aa7bcef7bd632edaf5a326d4c6085417282d133f0000000000001976a914c8f57d6b8bc08fa211c71b8d255e7c4b25bd432288ac02473044022037059673792d5af9ab1cf5fc8ccf3c1c1ad300e9e6c25edda7a172e455d49e07022046d2c2638c129a8c9a54ca5adb5df01bde564066c36edade43c3845b3d25940101210202ca6c82b9cc52f7a8c34de6a6ccd807d8437a8368ddf7638a2b50002e745b360247304402207b3d3c39ee66bdaa509094072ae629794bd7ef0f14694f0e3695d89ed573c57202205cc9b6d059500ccf621621a657115e33c51064efad2dcf352ad32c69b0ae6ab301210202ca6c82b9cc52f7a8c34de6a6ccd807d8437a8368ddf7638a2b50002e745b3670360c00"),
            prev_txs: vec![
            get_tx_from_hex("01000000000101b6d971c9ca363c5f901780d578bd0449d74b80bb565f367d56278c3b1601f94301000000000000000001f41400000000000016001460ac2a83f14bdc2016edf615138aabdd52d6c331024730440220560c4bdf1acc416517bd9d50ef65f0a99ac1633a5b1a7a3cb69ee486ed688a3a022079db25e85e6b34690456ad49f952302a80e1c146a7bc7af5387e92c2d4277c7a01210281bfdda07273f79522c04bff9e43c03655ebf96e482c8f3e262ccb5551c969f200000000"),
            get_tx_from_hex("02000000000101b6d971c9ca363c5f901780d578bd0449d74b80bb565f367d56278c3b1601f9430000000000fdffffff019e5700000000000016001460ac2a83f14bdc2016edf615138aabdd52d6c331014079a93a95b32520c99a08cfae6f1dfca31242359ca42ba56873cf2be60f472ea330ab7273753602fa362ce106287b365bae5542cb7358157641d8e2a7a052245400000000")
            ],
            expected_wallets: HashSet::from([WalletType::Electrum]),
        },
            // Ledger: C1094c70a9b23ca5d755234cffefca69f639d7a938f745dfd1190cc9c9d8b5ad
            TestVector {
                tx: get_tx_from_hex("010000000001039201ee164de0fe87bb1557be1b59270210ac793869d3e5149aa8c2d02b5d47d40000000000000000002becf7dd346f05756bba071eb894ccbf74f5ae9ca24b4a11159188f6b9b6f4850000000000000000008dc5773f385757f87bee0c4b64b5b85f4a12af0a6fa396cf18d50d8cb43b54af0000000000000000000298180100000000001976a9149c4075e0b1718eceb2322cfa1a8ab25b033a8aa988acf90c000000000000160014d0202edd81a21eab5a1637a616d5fcaccceea876024730440220630d494285d69bf6897f1b9326c034f899a6e1bc6485c925b5dcf1843a287daa022039cc491eff85a22d9e056017ca4e8873f8cec15985b5c8afcd7d2a867cc5d9210121033053287e92b72914ad0f95788112e028fb3c05de55e07ee19e66270568d871df0247304402200bd6e3104f853408de60dad1bcbbbade32f6e87a13736c5ef91652aa1ed5ac2302201dff726970330dd7608adaec9376cfe6b75a52d3c2c4ef56ccab0e8f1c138bdf0121029962e24537d5c9de63269f90fa6d89cd8b46a1580f7c7d30ab9e7990c668f92c0247304402207cde943346d08076876825b7b9763effce507a890f9c8c388d1c9b9d21f804bd02203f1f84b6264328e17d57d46ae006bc495a6417a1c8e66305e557c435e49771eb012103629299e79f95dec998663d5bd2cb9856726c81bde98791aa0622253510ed2ec500000000"),
                prev_txs: vec![
                    get_tx_from_hex("02000000000101160940344ab4e4c19877910c3584c57a1899a2903031056c9df0c68568d710080000000000fdffffff029442000000000000160014ba2ec40badac5c116a3aaa3e5ef52196e7d358af4c39000000000000160014b749341796e04d189fb7a9f3f4b56a71432b939202473044022078603bb9313bbe500e8599c305e7cc18f71a6abfa62890e4177aa3193094e34002200127ac6bfd56df9a29f1fcc2c655d153b3ee45c462e9e63844900fcdb2f27278012103b6e92d92aef77e32076052a4376bd2ce5fd78a18344b9df1db5c8c809991cee600000000"),
                    get_tx_from_hex("02000000011d040c7807779db11afc738beba87aed8104bc6bd30f892d8528ebfc79177b04000000006b483045022100f39d0f64f73bd335e014d13ed46e4cbacae89b0b014d7eb08b1eacfd7148da0a0220286699c7f12d8e1ef6770971b2aa19f4864bdeb1ea9e5137ea4138c4c7e9294f0121024b48ce8bdd016ce2e1538d0d4c9570eab7ecfedab348e8d89c92b88cd35fa0ebffffffff01d7ad0000000000001600145452750cd65d903f76e4bdbb99850584ade8357400000000"),
                    get_tx_from_hex("02000000000102c4ceb3f8be27f4af334cd6a1a1bf6cdf47a4937e54e3d549d08cb927edbfd5010000000000fdffffff9201ee164de0fe87bb1557be1b59270210ac793869d3e5149aa8c2d02b5d47d40100000000fdffffff01ae46000000000000160014b9de4f9f5c61e643fbc078c90beb6162b40abf4e02483045022100c3ab67bd13cbdfad7352ac514de1a02923834f40d0bbfc093d695c6205166cbb022010c13d427fc9d3ffcbb883fa849f6de22e513883782f2d57445335885bd013fe012103b6e92d92aef77e32076052a4376bd2ce5fd78a18344b9df1db5c8c809991cee602483045022100a1957c757c983306de87357d8a541ca659495b2b441db3a9fc9fd3622033ac1e02207394dc48c19d9c55348f076780ed475686d8a5f5365054dd94756929fb5e883d012102ed13f37ca6c7a478b120b5cc126828a145285a7273f1c75994517838e31064fe00000000"),
                ],
                expected_wallets: HashSet::from([WalletType::Ledger]),
            },
            // Trezor: 87670b12778d17c759db459479d66acfd1c4d444094270991d8e1de09a56cc7c
            TestVector {
                tx: get_tx_from_hex("01000000000103c54d8c88e4f5d43bd0afd365ab8af7688af9ca8d5c10dcb86519a924dd3a12e30000000000fdffffffc54d8c88e4f5d43bd0afd365ab8af7688af9ca8d5c10dcb86519a924dd3a12e30100000000fdffffffc54d8c88e4f5d43bd0afd365ab8af7688af9ca8d5c10dcb86519a924dd3a12e30200000000fdffffff03cf0a000000000000160014b47e4a3828865a23bb63da619b40bc3ec586480bb471000000000000160014eee06789bad1948746d16d69f6e698c99f62c341b4710000000000001976a9145b3263a7adcbd55ea653edfc4e4c04945a303a3788ac02483045022100a24d87256cdf7d63e526f7832282341d8d6c727c7c6aba536d7fa89a39522a4f022049a9e4d92c41fd99edd17c0f8614fd8421413b71e763f90dba6fb164a062a8b30121020c0bd6c738c36c415734e2d05614f861a083970c7cbe4a7b1db2bea740a9e54602473044022018234159f2a1085eab3f318a8596ecf9d3cbfeec3d3f46b3c47bc30bb3946c6d0220278c82c5bbdf1bef7ceb39bf904ffe72f88c43af598096b2569c1f1a51d67d6c0121020c0bd6c738c36c415734e2d05614f861a083970c7cbe4a7b1db2bea740a9e54602483045022100c1df2dbedcf0dc8c9b19098aeb9e6b2daead5b17bfd038922fa6480cc90c529202206fb4f7c0c81ed56eadc8e5771584fd36a877ffb750151a4b0ffbc5e16ab311b00121020c0bd6c738c36c415734e2d05614f861a083970c7cbe4a7b1db2bea740a9e54600000000"),
                prev_txs: vec![
                    get_tx_from_hex("0200000001adb5d8c9c90c19d1df45f738a9d739f669caefff4c2355d7a53cb2a9704c09c1000000006a47304402205825a5dcf15947113796f2da4f891ad39d5f1f761f4716770143cd470610e1ec0220261e1abe8ecf908ee718149d3587e9440ce96d9c8e680b34f306b8a405c2ae470121020b8a58237f6650d658730f5945c5fa9284c494040fefd8b6f33a2ac49862aa42ffffffff03895d00000000000016001444e650ca651d519813b57dc387a54b2c33016520cf4200000000000016001444e650ca651d519813b57dc387a54b2c33016520f46400000000000016001444e650ca651d519813b57dc387a54b2c3301652000000000"),
                ],
                expected_wallets: HashSet::from([WalletType::Trezor])
            },
            // Blue wallet: 1bf659e17568e48d6f47bb5470bc8df567cfe89d79c6e38cafbe798f43d5da22
            TestVector {
                tx: get_tx_from_hex("02000000000103570a26bfae0867b97212558189f80cdd44a2a24ff9d76b6dac599a73ed84d22f000000000000000080570a26bfae0867b97212558189f80cdd44a2a24ff9d76b6dac599a73ed84d22f010000000000000080570a26bfae0867b97212558189f80cdd44a2a24ff9d76b6dac599a73ed84d22f02000000000000008003a0860100000000001600147d2741001a5502d0db282c640d376ea7c5c5ba75a00f000000000000160014b4bf9b7ceab50cf7474b260aee1f5d880773b0e12ca100000000000016001442d0b6bc4040fd50aaadf3c6616d9ae0c42fa8db02483045022100fe6f638daa02a2de220ae87ffe212f55a0587147370284db8fa0c73f0a9f569402207b97624856cf66e1649c6459273ad3b0221906e1478154f0c7c9323e32f6fa65012103f307c3e3031babd35634a0f7989798ff6523d9267408828405f4873a10fde8ee02483045022100d4b3ac0e3a3eaa22667ada79693a322530b174e9e5821f0de29afdd1efbe1c4b022077f3eb4b7ea2a6eb49db2ba05c7ec8f461f14f2c4b8303ace17f12d17124aa2a012103bb5d910d5d7a336e8cc30effbca4a7bc7e01febd558523f709d62bb31c3215d40247304402203081506178cfe98d2b4ebeb17d89a3f9ad06966118fdffc01e173a1bd030c6950220667ac8c26f24e9e176aabe840e563e83b8112279b101373b5493e915fa5b29fb0121021ea4ff443e6b5db8c95ed934bf113fc6e5d740d166eb66aa6a5accbd990e064500000000"),
                prev_txs: vec![
                    get_tx_from_hex("020000000001013f17fa5fdc451e6fba6ac2fa02592af9ba8ee5f69b400f3559e23bc68ab8db2b0000000000000000800450c300000000000016001471e2c1575903a000d1486f9cbec0a245ecb9c19e50c3000000000000160014b536927be1e633e6674e1f36b8c8ee310adf2da150c3000000000000160014addbf648bada5bceca425289105731b09f434347cd9900000000000016001411385cc2c893fdef44ef6dd458241b19e5b3ffd202483045022100f42fe40dbacc20e40cd2e4c1ba86e3c38afec96528681af5335fa8c7c33aa6aa02202af9c25393097cd93a83a37d7a24702e302405a047b9e9f166209deb13ec821701210386ccea785809b6e69a1ed483c119e993a425a8bb100042f9f3d0dffda283a24700000000"),
                ],
                expected_wallets: HashSet::from([WalletType::BlueWallet])
            },
            // Exodus: 6f8c37db6ed88bfd0fd483963ebf06c5557326f8d2a3617af5ceba878442e1ad
            TestVector {
                tx: get_tx_from_hex("020000000001011309192e20a892daee269de43babb203a1ff68ae996406ca8b56ed9e8bca7d810000000000ffffffff02e91a000000000000160014fe3f8293b01b1d32db8dfc5ccd9a595e5af189b26f33000000000000160014ffed07852461fcef0ef3e2dd6ed598614037bb2902483045022100984153898e29ab101b666443ba1ca73f823ffd951347257f183afeeb5edac83a02204df7a36fb67d71089cf9d34be8c9c1ff7e8a30b33b96023e55e230c573f4f5bb01210315d9ffabd251ae57cd2a6843bf207e73ac95eeda9db75043bc0d18306f43be4d00000000"),
                prev_txs: vec![
                    get_tx_from_hex("020000000001017cca6cb0ed3a291dc8f385ba17100ea2749e56aea344dae6ded3bcd56a5af91600000000000000008001125b000000000000160014ffed07852461fcef0ef3e2dd6ed598614037bb2902483045022100ef12adecd8ada80560d64421707c653b19d11039e3a54e989433b8dc5d8aadb70220448d557e548767ee0652851e81dab1fe732c5d0af85634715956e397dcd25548012103a7a4f8c99a2ddf4fde317023fb73cee4d1b3191a20e722af88614857688f4f8400000000"),
                ],
                expected_wallets: HashSet::from([WalletType::Exodus])
            },
        ];
        fn do_test(test_vector: TestVector) {
            let (wallets, reasoning) = detect_wallet(&test_vector.tx, &test_vector.prev_txs);
            let expected_wallets = test_vector.expected_wallets;
            println!("wallets: {:?}", wallets);
            println!("reasoning: {:?}", reasoning);
            assert_eq!(wallets, expected_wallets);
        }

        for test_vector in test_vectors {
            do_test(test_vector);
        }
    }
}
