//! Q240 — the pin under the ERC-20 allowance rule.
//!
//! # What is being pinned, and why it needs pinning
//!
//! antseal approves the payment vault for the **exact quoted total**.
//! Upstream approves `U256::MAX` at every call site it has. The two clients
//! run the *identical* algorithm — query the allowance, compare, approve if
//! short — and differ only in the amount, which is why the difference is so
//! easy to erase by accident: "just pass `U256::MAX` like upstream does" is
//! a one-token change that looks like alignment and is actually the reversal
//! of a ruled trade.
//!
//! The trade is ruled in `docs/threat-model.md` §2.3, and it is a real one
//! in both directions. Exact costs anonymity: an exact allowance is consumed
//! by its own payment, so a fresh, non-round `Approval` is emitted on a
//! public and permanent chain before essentially every seal, and an address
//! that does that is separable from the general Autonomi payer population.
//! Unlimited costs a standing allowance the tool ships no command to revoke.
//! §2.3 chooses exact. This file is what makes the choice survive a
//! refactor.
//!
//! Before this file existed the behaviour was held in place by nothing:
//! four source hits inside `ant_backend.rs` and zero assertions anywhere.
//!
//! # The two halves, and why neither is sufficient alone
//!
//! - **The rule half** drives [`allowance_to_approve`], the free function
//!   that decides the amount. It catches a changed *rule* — unlimited,
//!   rounded, off-by-one, or a short-circuit that has stopped meaning what
//!   it says.
//! - **The call-site half** reads `src/ant_backend.rs` as text and asserts
//!   the adapter's single `approve_to_spend_tokens` call still passes the
//!   rule's output and nothing else. It catches a changed *call site* — an
//!   amount inlined past the rule — which the rule half cannot see, because
//!   a bypassed function keeps returning the right answer to nobody.
//!
//! A pin with only the first half would stay green while the shipped
//! approve became unlimited. That is this project's dominant defect class
//! and it is the reason the second half is here.
//!
//! # What this file does NOT cover
//!
//! It does not observe a real `approve` transaction. The allowance is
//! EVM-side, inside the adapter, and is deliberately **not** on the
//! `StorageBackend` seam, so `MockBackend` cannot emit one — the seam
//! carries quote/pay/finalize/get/balances and nothing about token
//! approvals. What runs here is the rule that decides the amount, tied to a
//! quote a real backend produced. Watching the transaction itself is
//! `tests/devnet_backend.rs`'s territory, on a local devnet.
//!
//! Everything here runs in the DEFAULT feature set: no `ant-backend`, no
//! upstream graph, **no live network and no spend of any kind**, on
//! `MockBackend`'s own feature set (project rule 1).

use std::path::Path;

use antseal_net::test_util::{MockBackend, block_on};
use antseal_net::{Blob, BlobCost, CostQuote, StorageBackend, allowance_to_approve};

/// Totals shaped like real quotes: 18-decimal atto-ANT, none of them round.
/// The non-roundness matters — it is half of what makes the on-chain
/// `Approval` value distinctive — so the fixtures must not be round either.
///
/// `u128::MAX` is deliberately NOT a fixture: it is the unlimited arm's own
/// value, so a total equal to it would make the exact rule and the reversal
/// indistinguishable — the assertion below could not tell them apart.
const NON_ROUND_TOTALS: [u128; 5] = [
    1,
    7,
    1_234_567_890_123_456_789,
    999_999_999_999_999_999_999,
    340_282_366_920_938_463_463_374_607_431_768_211_454, // u128::MAX - 1
];

/// Granularities a "round it up" implementation would plausibly pick,
/// spanning sub-gwei to whole-ANT.
const GRANULARITIES: [u128; 6] = [
    1_000,
    1_000_000,
    1_000_000_000,
    1_000_000_000_000,
    1_000_000_000_000_000,
    1_000_000_000_000_000_000,
];

/// `ceil(value / granularity) * granularity`, saturating.
fn round_up(value: u128, granularity: u128) -> u128 {
    match value % granularity {
        0 => value,
        remainder => value.saturating_add(granularity - remainder),
    }
}

/// The adapter source, read as text for the call-site half.
fn adapter_source() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/ant_backend.rs");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("cannot read {} for the call-site pin: {e}", path.display()))
}

// ---------------------------------------------------------------------------
// The rule half
// ---------------------------------------------------------------------------

/// The amount is the exact total. Not unlimited, not rounded, not adjusted.
#[test]
fn the_approved_amount_is_the_exact_quoted_total() {
    for total in NON_ROUND_TOTALS {
        let approved = allowance_to_approve(0, total).unwrap_or_else(|| {
            panic!("a zero standing allowance must require an approve for {total} atto")
        });

        assert_eq!(
            approved, total,
            "the approve amount must be the exact quoted total (Q240, threat-model §2.3); \
             got {approved} atto for a total of {total} atto"
        );
        assert_ne!(
            approved,
            u128::MAX,
            "the approve amount must never be unlimited — that is upstream's shape \
             (evmlib approves U256::MAX) and reversing to it hands the payment vault a \
             standing allowance antseal ships no command to revoke"
        );
    }
}

/// A rounded-up allowance is the arm §2.3 declines. It must not appear by
/// stealth at any granularity a rounding implementation would pick.
#[test]
fn the_approved_amount_is_never_rounded_up_to_any_granularity() {
    let mut compared = 0usize;
    for total in NON_ROUND_TOTALS {
        for granularity in GRANULARITIES {
            let rounded = round_up(total, granularity);
            if rounded == total {
                // Already a multiple: this granularity cannot distinguish
                // the arms for this total, so it is not evidence either way.
                continue;
            }
            compared += 1;
            let approved = allowance_to_approve(0, total).unwrap_or_else(|| {
                panic!("a zero standing allowance must require an approve for {total} atto")
            });
            assert_ne!(
                approved, rounded,
                "the approve amount is rounded up to a granularity of {granularity} atto \
                 ({total} -> {rounded}). §2.3 prices and DECLINES the rounded arm: it buys \
                 back approve cadence with exactly as much standing allowance, and it does \
                 not buy the anonymity, because every non-U256::MAX approval is outside the \
                 upstream crowd whether it is round or not. Changing this needs a decision \
                 record, not a patch"
            );
        }
    }
    for total in NON_ROUND_TOTALS {
        assert_eq!(
            allowance_to_approve(0, total),
            Some(total),
            "and the amount that is approved instead is the exact total, unrounded"
        );
    }
    assert!(
        compared >= 30,
        "the rounding fixtures degenerated: only {compared} arm comparisons were made, so \
         this assertion is not exercising what it claims to"
    );
}

/// The short-circuit means what it says: no approve exactly when the
/// standing allowance already covers the total, and one otherwise.
#[test]
fn the_short_circuit_fires_only_when_the_standing_allowance_already_covers_the_total() {
    let total = 1_234_567_890_123_456_789u128;

    assert_eq!(
        allowance_to_approve(total, total),
        None,
        "an allowance exactly equal to the total covers it — no approve"
    );
    assert_eq!(
        allowance_to_approve(total + 1, total),
        None,
        "an allowance above the total covers it — no approve"
    );
    assert_eq!(
        allowance_to_approve(u128::MAX, total),
        None,
        "a standing unlimited allowance covers everything — no approve. This is the arm \
         upstream takes, and the reason its clients approve once per address ever"
    );
    assert_eq!(
        allowance_to_approve(total - 1, total),
        Some(total),
        "one atto short is short: approve, and approve the exact total"
    );
    assert_eq!(
        allowance_to_approve(0, total),
        Some(total),
        "the normal case — a consumed allowance is zero"
    );
    assert_eq!(
        allowance_to_approve(0, 0),
        None,
        "nothing to pay is nothing to approve"
    );
}

/// The fingerprint itself, pinned as a sequence: because an exact allowance
/// is consumed by its own payment, every seal emits its own `approve`.
///
/// This is the observable §2.3 rules on, so it is asserted as an observable
/// rather than inferred from the rule. If this ever goes green with fewer
/// approvals than seals, the trade has changed and §2.3 is stale.
#[test]
fn an_exact_allowance_is_consumed_by_its_own_payment_so_every_seal_re_approves() {
    // Ten seals at ten different non-round costs, run against a ledger that
    // behaves the way ERC-20 does: `transferFrom` decrements the allowance
    // by what it moved, and the payment moves exactly the approved total.
    let seals: [u128; 10] = [
        11_111_111_111_111_111,
        22_222_222_222_222_223,
        3_333_333_333_333_337,
        444_444_444_444_444_449,
        55_555_555_555_555_551,
        666_666_666_666_666_667,
        7_777_777_777_777_777,
        88_888_888_888_888_889,
        999_999_999_999_999_991,
        123_456_789_987_654_321,
    ];

    let mut standing_allowance = 0u128;
    let mut approvals: Vec<u128> = Vec::new();

    for total in seals {
        if let Some(amount) = allowance_to_approve(standing_allowance, total) {
            approvals.push(amount);
            standing_allowance = amount;
        }
        // The payment. `payForQuotes` moves exactly `total` by
        // `transferFrom`, which decrements the allowance by what it moved.
        assert!(
            standing_allowance >= total,
            "the allowance rule left {standing_allowance} atto standing against a payment of \
             {total} atto — the approve it raised does not cover the payment it was raised for"
        );
        standing_allowance -= total;
    }

    assert_eq!(
        approvals.len(),
        seals.len(),
        "the short-circuit fired: {} approvals for {} seals. An exact allowance is consumed \
         by its own payment, so the count must match — if it no longer does, the amount rule \
         has changed and docs/threat-model.md §2.3's fingerprint is wrong",
        approvals.len(),
        seals.len()
    );
    assert_eq!(
        approvals,
        seals.to_vec(),
        "each approval must carry its own seal's exact total, in order"
    );
    assert_eq!(
        standing_allowance, 0,
        "an exact allowance leaves nothing standing between seals — that is the whole \
         wallet-hygiene half of the trade"
    );
}

// ---------------------------------------------------------------------------
// Tied to a quote a backend actually produced (MockBackend, no network)
// ---------------------------------------------------------------------------

/// The rule's input is a real quote's total, not a number invented by this
/// test: quote three blobs on `MockBackend`, sum the payment lines the way
/// `pay()` does, and require the rule to approve exactly that.
#[test]
fn the_rule_approves_a_mock_backend_quotes_exact_total() {
    let mock = MockBackend::new().with_base_price(1_000_000_007);
    let blobs: Vec<Blob> = [b"alpha".to_vec(), b"beta".to_vec(), b"gamma".to_vec()]
        .into_iter()
        .map(|bytes| Blob::new(bytes).expect("fixture blobs are far under the chunk cap"))
        .collect();

    let quote: CostQuote = block_on(mock.quote_batch(&blobs)).expect("MockBackend quotes offline");

    // The sum `pay()` forms: every non-zero payment line, in blob order.
    let mut summed = 0u128;
    let mut lines = 0usize;
    for blob in &quote.blobs {
        if let BlobCost::Priced { payments, .. } = &blob.cost {
            for entry in payments {
                if entry.amount_atto > 0 {
                    summed = summed.saturating_add(entry.amount_atto);
                    lines += 1;
                }
            }
        }
    }

    assert!(
        lines >= 3,
        "the fixture produced {lines} non-zero payment line(s); with fewer than one per blob \
         this test is not measuring a real total"
    );
    assert_eq!(
        summed, quote.total_ant_atto,
        "the quote's own total must be the sum of its payment lines"
    );
    assert!(summed > 0, "a priced quote costs something");

    assert_eq!(
        allowance_to_approve(0, summed),
        Some(summed),
        "the approve raised for this quote must be the quote's exact total"
    );
    assert_eq!(
        allowance_to_approve(summed, summed),
        None,
        "and a standing allowance that already covers it raises nothing"
    );
}

// ---------------------------------------------------------------------------
// The call-site half
// ---------------------------------------------------------------------------

/// The adapter has exactly one approve call site and it passes the rule's
/// output — no literal, no second path.
///
/// Text, not types, because the defect this catches is an amount inlined
/// past the rule, and an inlined amount type-checks perfectly.
#[test]
fn the_only_approve_call_site_passes_the_rules_output() {
    let source = adapter_source();

    let call_sites = source.matches("approve_to_spend_tokens(").count();
    assert_eq!(
        call_sites, 1,
        "src/ant_backend.rs has {call_sites} approve call site(s); the allowance rule is \
         pinned at one, and a second site is a second policy nothing checks"
    );

    let binding =
        "let Some(amount_atto) = allowance_to_approve(saturate_u256(current), total_atto)";
    assert!(
        source.contains(binding),
        "the approve amount is no longer bound from `allowance_to_approve`. That function is \
         the ruled rule (Q240, docs/threat-model.md §2.3) and the only place the amount may \
         be decided; expected to find:\n    {binding}"
    );

    let call = ".approve_to_spend_tokens(vault, U256::from(amount_atto))";
    assert!(
        source.contains(call),
        "the approve call site no longer passes the rule's output. Whatever it passes now is \
         an allowance policy that no test can see — which is exactly the state Q240 was \
         opened to end; expected to find:\n    {call}"
    );
}

/// `U256::MAX` appears in the adapter only where it is being described, never
/// where it is being passed.
///
/// This is the specific reversal the row names: the "simplification" toward
/// upstream's shape. It reads as alignment and it is a silent reversal of a
/// ruled trade, so it is asserted against directly.
#[test]
fn the_adapter_never_passes_an_unlimited_allowance() {
    let source = adapter_source();
    let mut offenders: Vec<(usize, String)> = Vec::new();
    let mut described = 0usize;

    for (index, line) in source.lines().enumerate() {
        if !line.contains("U256::MAX") {
            continue;
        }
        let trimmed = line.trim_start();
        // Prose — a doc comment or an ordinary comment — is where naming the
        // unlimited arm is not only allowed but wanted.
        if trimmed.starts_with("//") {
            described += 1;
            continue;
        }
        offenders.push((index + 1, line.trim().to_string()));
    }

    assert!(
        offenders.is_empty(),
        "src/ant_backend.rs mentions U256::MAX in code, not prose, at {offenders:?}. Approving \
         an unlimited allowance is upstream's arm (evmlib-0.9.0/src/wallet.rs:421 and three \
         sibling sites); antseal declines it in docs/threat-model.md §2.3 because a standing \
         unlimited allowance is one this tool ships no command to revoke. Reversing that needs \
         a decision record"
    );
    assert!(
        described > 0,
        "src/ant_backend.rs no longer names U256::MAX anywhere, so this check has nothing to \
         distinguish and would pass over a file that had dropped the contrast entirely — the \
         module docs are supposed to say which arm was declined"
    );
}
