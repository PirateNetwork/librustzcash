use alloc::vec::Vec;
use core::mem::size_of;

use ::transparent::{address::Script, bundle as transparent};
use corez::io;
use proptest::{prelude::*, strategy::ValueTree, test_runner::TestRunner};
use sapling::{
    bundle::{Authorized, Bundle, OutputDescription, SpendDescription, testing::arb_bundle},
    value::{NoteValue, ValueCommitTrapdoor, ValueCommitment},
};
use zcash_encoding::{CompactSize, MAX_COMPACT_SIZE};
use zcash_note_encryption::{ENC_CIPHERTEXT_SIZE, OUT_CIPHERTEXT_SIZE};
use zcash_protocol::{
    consensus::BranchId,
    value::{MAX_BALANCE, MAX_MONEY, ZatBalance, Zatoshis},
};

use crate::transaction::{
    Transaction, TransactionData, TxVersion,
    components::{GROTH_PROOF_SIZE, sprout},
};

/// A small CompactSize value occupies one byte.
const SMALL_COUNT_SIZE: usize = 1;
/// CompactSize switches from a single byte to its u16 form at this count.
const FIRST_EXTENDED_COUNT: usize = 253;
const LAST_SMALL_COUNT: usize = FIRST_EXTENDED_COUNT - 1;
/// Canonical field and group encodings used by the v4 Sapling components.
const FIELD_SIZE: usize = 32;
const SIGNATURE_SIZE: usize = 64;
const AMOUNT_SIZE: usize = size_of::<u64>();
const HEADER_SIZE: usize = 2 * size_of::<u32>();
/// This fixture has no inputs and one output with an empty script.
const TRANSPARENT_VALUE_START: usize = HEADER_SIZE + 2 * SMALL_COUNT_SIZE;
const TRANSPARENT_OUTPUT_SIZE: usize = AMOUNT_SIZE + SMALL_COUNT_SIZE;
/// Header, transparent vector counts/output, lock time, and expiry height.
const SAPLING_START: usize =
    TRANSPARENT_VALUE_START + TRANSPARENT_OUTPUT_SIZE + 2 * size_of::<u32>();
const SPEND_COUNT_START: usize = SAPLING_START + AMOUNT_SIZE;
const SPENDS_START: usize = SPEND_COUNT_START + SMALL_COUNT_SIZE;
/// cv, anchor, nullifier, rk, proof, and spend authorization signature.
const SPEND_SIZE: usize = 4 * FIELD_SIZE + GROTH_PROOF_SIZE + SIGNATURE_SIZE;
/// cv, cmu, epk, encrypted note, outgoing ciphertext, and proof.
const OUTPUT_SIZE: usize =
    3 * FIELD_SIZE + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE + GROTH_PROOF_SIZE;

fn bundle(spends: usize, outputs: usize) -> Bundle<Authorized, ZatBalance> {
    let mut runner = TestRunner::deterministic();
    let seed = arb_bundle(ZatBalance::zero())
        .prop_filter(
            "two distinct spends and outputs for reordering tests",
            |bundle| {
                bundle.as_ref().is_some_and(|bundle| {
                    bundle.shielded_spends().len() >= 2
                        && bundle.shielded_outputs().len() >= 2
                        && bundle.shielded_spends()[0].nullifier()
                            != bundle.shielded_spends()[1].nullifier()
                        && bundle.shielded_outputs()[0].cmu() != bundle.shielded_outputs()[1].cmu()
                })
            },
        )
        .new_tree(&mut runner)
        .unwrap()
        .current()
        .unwrap();

    // Reuse the protocol crate's structurally valid encodings. Cycling the
    // generated entries also exercises counts beyond its normal small range.
    Bundle::from_parts(
        seed.shielded_spends()
            .iter()
            .cycle()
            .take(spends)
            .cloned()
            .collect(),
        seed.shielded_outputs()
            .iter()
            .cycle()
            .take(outputs)
            .cloned()
            .collect(),
        *seed.value_balance(),
        *seed.authorization(),
    )
    .unwrap()
}

fn encoded(bundle: &Bundle<Authorized, ZatBalance>) -> Vec<u8> {
    let transparent = transparent::Bundle {
        vin: vec![],
        vout: vec![transparent::TxOut::new(Zatoshis::ZERO, Script::default())],
        authorization: transparent::Authorized,
    };
    let tx = TransactionData::<crate::transaction::Authorized>::from_parts(
        TxVersion::V4,
        BranchId::Canopy,
        0,
        0u32.into(),
        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
        Zatoshis::ZERO,
        Some(transparent),
        None,
        Some(bundle.clone()),
        None,
    )
    .freeze()
    .unwrap();
    let mut bytes = Vec::new();
    tx.write(&mut bytes).unwrap();
    bytes
}

fn reused(bytes: &[u8], bundle: &Bundle<Authorized, ZatBalance>) -> io::Result<Transaction> {
    Transaction::temporary_zcashd_read_v4_with_sapling(bytes, BranchId::Canopy, bundle)
}

#[test]
fn matching_reader_preserves_hashes_and_fields_at_count_boundaries() {
    for (spends, outputs) in [
        (0, 1),
        (1, 0),
        (1, 1),
        (LAST_SMALL_COUNT, FIRST_EXTENDED_COUNT),
        (FIRST_EXTENDED_COUNT, LAST_SMALL_COUNT),
    ] {
        let bundle = bundle(spends, outputs);
        let bytes = encoded(&bundle);
        // The ordinary reader remains an independent decoder reference.
        let reference = Transaction::read(&bytes[..], BranchId::Canopy).unwrap();
        let actual = reused(&bytes, &bundle).unwrap();
        assert_eq!(reference.txid(), actual.txid());
        assert_eq!(reference.auth_commitment(), actual.auth_commitment());
        let mut rewritten = Vec::new();
        actual.write(&mut rewritten).unwrap();
        assert_eq!(bytes, rewritten);
    }
}

#[test]
fn mismatched_fields_cannot_reuse_a_different_bundle() {
    let bundle = bundle(2, 2);
    let bytes = encoded(&bundle);
    let output_count_start = SPENDS_START + bundle.shielded_spends().len() * SPEND_SIZE;
    let outputs_start = output_count_start + SMALL_COUNT_SIZE;
    let spend_fields = [
        0,
        FIELD_SIZE,
        2 * FIELD_SIZE,
        3 * FIELD_SIZE,
        4 * FIELD_SIZE,
        4 * FIELD_SIZE + GROTH_PROOF_SIZE,
    ];
    let output_fields = [
        0,
        FIELD_SIZE,
        2 * FIELD_SIZE,
        3 * FIELD_SIZE,
        3 * FIELD_SIZE + ENC_CIPHERTEXT_SIZE,
        3 * FIELD_SIZE + ENC_CIPHERTEXT_SIZE + OUT_CIPHERTEXT_SIZE,
    ];
    let offsets = [SAPLING_START, SPEND_COUNT_START, output_count_start]
        .into_iter()
        .chain(spend_fields.into_iter().map(|offset| SPENDS_START + offset))
        .chain(
            output_fields
                .into_iter()
                .map(|offset| outputs_start + offset),
        );
    for offset in offsets {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        assert!(reused(&changed, &bundle).is_err(), "offset {offset}");
    }

    let mut changed = bytes.clone();
    // The binding signature is still read after the empty JoinSplit vector.
    *changed.last_mut().unwrap() ^= 1;
    assert!(reused(&changed, &bundle).is_err());
    let mut changed = bytes.clone();
    for i in 0..SPEND_SIZE {
        changed.swap(SPENDS_START + i, SPENDS_START + SPEND_SIZE + i);
    }
    assert!(reused(&changed, &bundle).is_err());
    let mut changed = bytes;
    for i in 0..OUTPUT_SIZE {
        changed.swap(outputs_start + i, outputs_start + OUTPUT_SIZE + i);
    }
    assert!(reused(&changed, &bundle).is_err());
}

#[test]
fn malformed_counts_truncations_and_non_sapling_amounts_still_fail() {
    let bundle = bundle(1, 1);
    let bytes = encoded(&bundle);
    for length in 0..bytes.len() {
        assert!(Transaction::read(&bytes[..length], BranchId::Canopy).is_err());
        assert!(reused(&bytes[..length], &bundle).is_err());
    }
    // The u16 form is non-canonical for a count that fits in one byte.
    for offset in [SPEND_COUNT_START, SPENDS_START + SPEND_SIZE] {
        let mut changed = bytes.clone();
        changed.splice(
            offset..offset + SMALL_COUNT_SIZE,
            [FIRST_EXTENDED_COUNT as u8, 1, 0],
        );
        assert!(Transaction::read(&changed[..], BranchId::Canopy).is_err());
        assert!(reused(&changed, &bundle).is_err());
    }
    for amount in [u64::MAX, MAX_MONEY + 1] {
        let mut changed = bytes.clone();
        changed[TRANSPARENT_VALUE_START..TRANSPARENT_VALUE_START + AMOUNT_SIZE]
            .copy_from_slice(&amount.to_le_bytes());
        assert!(Transaction::read(&changed[..], BranchId::Canopy).is_err());
        assert!(reused(&changed, &bundle).is_err());
    }
    let mut changed = bytes;
    changed[..size_of::<u32>()].copy_from_slice(&TxVersion::V5.header().to_le_bytes());
    assert!(reused(&changed, &bundle).is_err());
}

#[test]
fn typed_count_precheck_retains_the_wire_decoders_limit() {
    // Exercise the count precheck without allocating enormous bundles.
    for count in [
        MAX_COMPACT_SIZE as usize - 1,
        MAX_COMPACT_SIZE as usize,
        MAX_COMPACT_SIZE as usize + 1,
        usize::MAX,
    ] {
        let mut encoded = [0; SMALL_COUNT_SIZE + size_of::<u64>()];
        CompactSize::write(&mut encoded[..], count).unwrap();
        assert_eq!(
            CompactSize::read(&encoded[..]).is_ok(),
            count <= MAX_COMPACT_SIZE as usize
        );
    }
}

#[test]
fn typed_small_order_value_commitments_do_not_bypass_the_decoder() {
    let seed = bundle(1, 1);
    let cv = || {
        ValueCommitment::derive(
            NoteValue::from_raw(0),
            ValueCommitTrapdoor::from_bytes([0; FIELD_SIZE]).unwrap(),
        )
    };
    assert!(bool::from(cv().as_inner().is_small_order()));
    let spend = &seed.shielded_spends()[0];
    let output = &seed.shielded_outputs()[0];
    for bad_spend in [false, true] {
        let spends = if bad_spend {
            vec![SpendDescription::from_parts(
                cv(),
                *spend.anchor(),
                *spend.nullifier(),
                *spend.rk(),
                *spend.zkproof(),
                *spend.spend_auth_sig(),
            )]
        } else {
            seed.shielded_spends().to_vec()
        };
        let outputs = if bad_spend {
            seed.shielded_outputs().to_vec()
        } else {
            vec![OutputDescription::from_parts(
                cv(),
                *output.cmu(),
                output.ephemeral_key().clone(),
                *output.enc_ciphertext(),
                *output.out_ciphertext(),
                *output.zkproof(),
            )]
        };
        let invalid = Bundle::from_parts(
            spends,
            outputs,
            *seed.value_balance(),
            *seed.authorization(),
        )
        .unwrap();
        let bytes = encoded(&invalid);
        assert!(Transaction::read(&bytes[..], BranchId::Canopy).is_err());
        assert!(reused(&bytes, &invalid).is_err());
    }
}

#[test]
fn verification_key_rules_are_not_strengthened_or_weakened() {
    let seed = bundle(1, 1);
    let spend = &seed.shielded_spends()[0];
    // Compressed Jubjub identity: y=1, x sign=0. The ordinary reader accepts
    // this rk; its small-order rejection belongs to later consensus checks.
    let mut identity = [0; FIELD_SIZE];
    identity[0] = 1;
    let rk = redjubjub::VerificationKey::<redjubjub::SpendAuth>::try_from(identity).unwrap();
    let typed = Bundle::from_parts(
        vec![SpendDescription::from_parts(
            spend.cv().clone(),
            *spend.anchor(),
            *spend.nullifier(),
            rk,
            *spend.zkproof(),
            *spend.spend_auth_sig(),
        )],
        seed.shielded_outputs().to_vec(),
        *seed.value_balance(),
        *seed.authorization(),
    )
    .unwrap();
    let bytes = encoded(&typed);
    let expected = Transaction::read(&bytes[..], BranchId::Canopy).unwrap();
    assert_eq!(expected.txid(), reused(&bytes, &typed).unwrap().txid());

    let mut invalid = bytes;
    let rk_start = SPENDS_START + 3 * FIELD_SIZE;
    invalid[rk_start..rk_start + FIELD_SIZE].fill(0xff);
    assert!(Transaction::read(&invalid[..], BranchId::Canopy).is_err());
    assert!(reused(&invalid, &typed).is_err());
}

#[test]
fn joinsplit_fields_keep_the_original_reader_and_amount_bounds() {
    /// Each Sprout encrypted output occupies 601 bytes in a JoinSplit.
    const SPROUT_CIPHERTEXT_SIZE: usize = 601;
    /// vpub_old/new, nine field encodings, a Groth16 proof, two ciphertexts.
    const JOINSPLIT_SIZE: usize =
        2 * AMOUNT_SIZE + 9 * FIELD_SIZE + GROTH_PROOF_SIZE + 2 * SPROUT_CIPHERTEXT_SIZE;
    let bundle = bundle(1, 1);
    let seed = Transaction::read(&encoded(&bundle)[..], BranchId::Canopy).unwrap();
    let joinsplit = sprout::JsDescription::read(&[0; JOINSPLIT_SIZE][..], true).unwrap();
    let tx = TransactionData::<crate::transaction::Authorized>::from_parts(
        TxVersion::V4,
        BranchId::Canopy,
        0,
        0u32.into(),
        #[cfg(all(zcash_unstable = "nu7", feature = "zip-233"))]
        Zatoshis::ZERO,
        seed.transparent_bundle().cloned(),
        Some(sprout::Bundle {
            joinsplits: vec![joinsplit],
            joinsplit_pubkey: [0; FIELD_SIZE],
            joinsplit_sig: [0; SIGNATURE_SIZE],
        }),
        Some(bundle.clone()),
        None,
    )
    .freeze()
    .unwrap();
    let mut bytes = Vec::new();
    tx.write(&mut bytes).unwrap();
    assert_eq!(tx.txid(), reused(&bytes, &bundle).unwrap().txid());
    let joinsplit_start =
        SPENDS_START + SPEND_SIZE + SMALL_COUNT_SIZE + OUTPUT_SIZE + SMALL_COUNT_SIZE;
    for offset in [0, AMOUNT_SIZE] {
        let mut invalid = bytes.clone();
        invalid[joinsplit_start + offset..joinsplit_start + offset + AMOUNT_SIZE].fill(0xff);
        assert!(Transaction::read(&invalid[..], BranchId::Canopy).is_err());
        assert!(reused(&invalid, &bundle).is_err());
    }
}

fn assert_equivalent_transactions(reference: &Transaction, actual: &Transaction) {
    assert_eq!(reference.txid(), actual.txid());
    assert_eq!(reference.auth_commitment(), actual.auth_commitment());
    let mut expected = Vec::new();
    let mut rewritten = Vec::new();
    reference.write(&mut expected).unwrap();
    actual.write(&mut rewritten).unwrap();
    assert_eq!(expected, rewritten);
}

#[test]
fn generated_transactions_and_extreme_balances_match_the_ordinary_reader() {
    // Bound the deterministic corpus while varying every transaction component
    // supported by the existing Canopy transaction strategy.
    const GENERATED_TRANSACTIONS: usize = 32;
    let mut runner = TestRunner::deterministic();
    let strategy = crate::transaction::testing::arb_tx(BranchId::Canopy)
        .prop_filter("a reusable Sapling bundle", |tx| {
            tx.sapling_bundle().is_some()
        });
    for _ in 0..GENERATED_TRANSACTIONS {
        let tx = strategy.new_tree(&mut runner).unwrap().current();
        let mut bytes = Vec::new();
        tx.write(&mut bytes).unwrap();
        let reference = Transaction::read(&bytes[..], BranchId::Canopy).unwrap();
        let actual = reused(&bytes, tx.sapling_bundle().unwrap()).unwrap();
        assert_equivalent_transactions(&reference, &actual);
    }

    let seed = bundle(1, 1);
    for balance in [-MAX_BALANCE, -1, 1, MAX_BALANCE] {
        let bundle = Bundle::from_parts(
            seed.shielded_spends().to_vec(),
            seed.shielded_outputs().to_vec(),
            ZatBalance::from_i64(balance).unwrap(),
            *seed.authorization(),
        )
        .unwrap();
        let bytes = encoded(&bundle);
        let reference = Transaction::read(&bytes[..], BranchId::Canopy).unwrap();
        let actual = reused(&bytes, &bundle).unwrap();
        assert_equivalent_transactions(&reference, &actual);
        assert_eq!(
            *actual.sapling_bundle().unwrap().value_balance(),
            *bundle.value_balance()
        );
    }
}

#[test]
fn accepting_a_mutated_transaction_requires_ordinary_reader_equivalence() {
    let bundle = bundle(2, 2);
    let bytes = encoded(&bundle);
    let mut accepted = 0;
    let mut rejected = 0;
    // Change every byte in turn, including fields outside the reused bundle.
    // Those fields may change legitimately; successful reads must still agree.
    for offset in 0..bytes.len() {
        let mut changed = bytes.clone();
        changed[offset] ^= 1;
        match reused(&changed, &bundle) {
            Ok(actual) => {
                let reference = Transaction::read(&changed[..], BranchId::Canopy)
                    .unwrap_or_else(|_| panic!("only reuse accepted mutation at {offset}"));
                assert_equivalent_transactions(&reference, &actual);
                accepted += 1;
            }
            Err(_) => rejected += 1,
        }
    }
    assert!(accepted > 0, "exercise fields outside the reused bundle");
    assert!(rejected > 0, "exercise mismatches within the reused bundle");
}

struct FragmentedReader<'a> {
    remaining: &'a [u8],
    fragment_size: usize,
    interrupt_next: bool,
}

impl io::Read for FragmentedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.interrupt_next {
            self.interrupt_next = false;
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "retry this read",
            ));
        }
        self.interrupt_next = true;
        let count = buf.len().min(self.fragment_size).min(self.remaining.len());
        buf[..count].copy_from_slice(&self.remaining[..count]);
        self.remaining = &self.remaining[count..];
        Ok(count)
    }
}

#[test]
fn fragmented_interrupted_reads_preserve_hashes_and_trailing_bytes() {
    // Odd fragment sizes deliberately split field encodings at different offsets.
    const FRAGMENT_SIZES: [usize; 3] = [1, 7, 31];
    // Bytes belonging to the next message must remain unread after a transaction.
    const TRAILING_SENTINEL: [u8; 4] = [0xde, 0xad, 0xbe, 0xef];
    let bundle = bundle(1, 1);
    let mut bytes = encoded(&bundle);
    bytes.extend_from_slice(&TRAILING_SENTINEL);
    for fragment_size in FRAGMENT_SIZES {
        let mut original_stream = FragmentedReader {
            remaining: &bytes,
            fragment_size,
            interrupt_next: true,
        };
        let mut reused_stream = FragmentedReader {
            remaining: &bytes,
            fragment_size,
            interrupt_next: true,
        };
        let reference = Transaction::read(&mut original_stream, BranchId::Canopy).unwrap();
        let actual = Transaction::temporary_zcashd_read_v4_with_sapling(
            &mut reused_stream,
            BranchId::Canopy,
            &bundle,
        )
        .unwrap();
        assert_equivalent_transactions(&reference, &actual);
        assert_eq!(original_stream.remaining, TRAILING_SENTINEL);
        assert_eq!(reused_stream.remaining, TRAILING_SENTINEL);
    }
}
