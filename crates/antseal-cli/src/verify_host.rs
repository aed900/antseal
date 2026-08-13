//! `verify`'s network hosts (task U30) — the two collectors behind R21's
//! [`VerifyHost`] seam.
//!
//! R21's seam is deliberately **not** async and deliberately pure: its two
//! methods are *accessors over data the host has already collected*, because
//! `antseal-core` performs no I/O and the browser's `fetch` is async in a way
//! core cannot be. So the shape here is collect-then-run: this module does
//! the network work, [`CollectedInputs`] holds the results, and
//! [`crate::verify_out::run_verify`] reads them.
//!
//! # Neither collector can change a verdict
//!
//! - **`--online`** produces [`OnlineInputs`]: the **agreed** evidence and a
//!   probe log. Only agreement crosses into the evidence path —
//!   `OnlineBlockResult` has no failure variant by construction (D56 §3), so
//!   an unreachable or disagreeing endpoint is the *absence* of an entry.
//!   That is why D69 §3 R5's weather clause is a theorem rather than a check:
//!   a network outage cannot move `antseal verify`'s exit code, because the
//!   type that would carry the failure was never given a variant to put it
//!   in. The richer outcome stays in the probe log, which renders and gates
//!   nothing.
//! - **`--live`** produces [`LiveInputs`]: one row per stored blob. The
//!   storage-linkage layer gates no verdict (MVP-SPEC.md line 118 —
//!   *"storage is the product's bonus, not its proof"*), and D69 §3 R6
//!   forbids it moving the exit code. It cannot: [`LiveInputs`] is not a
//!   parameter of the rung fold.
//!
//! # D66: a probe failure never names a cause beyond its class
//!
//! `antseal-anchor`'s `EndpointFailure` carries endpoint-authored detail;
//! core's [`ProbeFailureClass`] carries a closed three-value class and the
//! endpoint's own configured URL. [`probe_failure`] is the narrowing, and it
//! is deliberate: an adversary-controlled endpoint must not get a byte
//! channel into a display line, and the wording for each class is core's.

use std::collections::BTreeMap;

use antseal_anchor::agree::{Agreement, EndpointFailure, EndpointPair};
use antseal_anchor::arbitrum::confirm::{ArbitrumConfirmation, confirm_arbitrum_tx};
use antseal_anchor::esplora::{fetch_agreed_header, into_online_block_result};
use antseal_anchor::http::HttpClient;
use antseal_core::anchor::model::OnlineEvidence;
use antseal_core::bundle::BundleV1;
use antseal_core::manifest::Manifest;
use antseal_core::verify::orchestration::{
    LiveBlobOutcome, LiveBlobRow, LiveInputs, OnlineInputs, VerifyHost,
};
use antseal_core::verify::overlay::{
    BlockProbe, EndpointProbeFailure, ProbeEndpoints, ProbeFailureClass, ProbeLog, ReceiptProbe,
};
use antseal_core::verify::plan::ProbePlan;
use antseal_net::{
    Address, LiveSubject, NetworkId, StorageBackend, StorageRecord, UnitKindTag, live_check,
};

use crate::error::CliError;

#[cfg(test)]
mod tests;

/// What one `verify` run's hosts collected — R21's seam, as a value.
///
/// Both layers default to "nothing was attempted", which is the honest state
/// for a mode that was not requested: R21 consults a method **only** when
/// [`VerifyModes`](antseal_core::verify::orchestration::VerifyModes) asks for
/// its layer, so an unrequested layer's inputs are never read at all.
pub struct CollectedInputs {
    online: OnlineInputs,
    live: LiveInputs,
}

impl CollectedInputs {
    /// Nothing collected — the offline default.
    ///
    /// Safe to hand to an offline run, whose host is never consulted;
    /// R21's `offline_mode_never_consults_the_host` proves that with a
    /// panicking implementation.
    #[must_use]
    pub fn none() -> Self {
        Self {
            online: OnlineInputs::new(
                OnlineEvidence::new(),
                ProbeLog::new(ProbeEndpoints::new(Vec::new(), false)),
            ),
            live: LiveInputs::none(),
        }
    }

    /// Attach an `--online` probe run's results.
    #[must_use]
    pub fn with_online(mut self, online: OnlineInputs) -> Self {
        self.online = online;
        self
    }

    /// Attach a `--live` check's rows.
    #[must_use]
    pub fn with_live(mut self, live: LiveInputs) -> Self {
        self.live = live;
        self
    }
}

impl VerifyHost for CollectedInputs {
    fn online_inputs(&self) -> OnlineInputs {
        OnlineInputs::new(self.online.evidence().clone(), self.online.probes().clone())
    }

    fn live_inputs(&self) -> LiveInputs {
        self.live.clone()
    }
}

// ---------------------------------------------------------------------------
// `--online` (A16 esplora + A17 Arbitrum, through their must-agree pairs)
// ---------------------------------------------------------------------------

/// Run the `--online` probes for one bundle.
///
/// **What to ask is not decided here.** Both halves come from
/// [`ProbePlan::from_bundle`], which is the same function R22's page reaches
/// through `verify_rendered`'s `plan` member (D132 §3 R4). One esplora probe
/// per height in `plan.blocks` — distinct and ascending, because two anchors
/// committed in the same block are one question and the probe log is keyed by
/// height — and one Arbitrum probe for `plan.receipt`, when the bundle carries
/// a receipt and this network has an RPC pair.
///
/// The rewrite changed no behaviour and that is the point: after it, *"the two
/// surfaces ask the same question"* is a property of there being **one
/// function** rather than of two lists agreeing today. It also means a defect
/// in that function is a defect in both surfaces at once and is invisible to a
/// gate that compares their renderings — see this module's `tests`, which
/// drives this collector against stub endpoints and reads what went out on the
/// wire (D132 §3 R9.2, §7.4).
///
/// Endpoints are the caller's: U4's `[verify] bitcoin_endpoints` /
/// `arbitrum_endpoints` overrides, or A16/A17's pinned defaults. `overridden`
/// is disclosed in the overlay, never inferred there.
///
/// Every failure is an *outcome*, never an error: this function is
/// infallible by design, because a probe that could fail the run would make
/// a third party's verification depend on a public endpoint's mood.
#[must_use]
pub fn probe_online(
    client: &HttpClient,
    bundle: &BundleV1<'_>,
    endpoints: &OnlineEndpoints,
    network: NetworkId,
) -> OnlineInputs {
    let mut evidence = OnlineEvidence::new();
    let mut probes = ProbeLog::new(ProbeEndpoints::new(
        endpoints.identities(),
        endpoints.overridden,
    ));

    let plan = ProbePlan::from_bundle(bundle);

    for height in plan.blocks {
        let agreement = fetch_agreed_header(client, &endpoints.bitcoin, height);
        // Only agreement crosses into the evidence path (D56 §3). The two
        // are recorded together so an `Agreed` probe whose evidence never
        // reached the evaluation cannot exist.
        if let Some(result) = into_online_block_result(&agreement) {
            evidence = evidence.with_block(height, result);
        }
        probes = probes.with_block(height, block_probe(&agreement));
    }

    // The receipt half comes from the same plan. `ReceiptTarget` carries the
    // 32 bytes beside the hex the page reads, so this path re-decodes nothing
    // and cannot disagree with what the page was told to fetch.
    if let Some(pair) = &endpoints.arbitrum
        && let Some(target) = &plan.receipt
    {
        let confirmation = confirm_arbitrum_tx(client, pair, network, target.tx_hash_bytes());
        if let Some(agreed) = confirmation.into_receipt_confirmation() {
            evidence = evidence.with_receipt(agreed);
        }
        probes = probes.with_receipt(receipt_probe(&confirmation));
    }

    OnlineInputs::new(evidence, probes)
}

/// The endpoint pairs one `--online` run uses, and whether they departed from
/// the pinned defaults.
///
/// The Arbitrum pair is optional because one network has none: the local
/// devnet's contracts are minted by the Anvil run that created it (S5), so
/// there is no public RPC pair to must-agree against. A receipt on that
/// network is simply not probed — `ReceiptProbe::NotAttempted`, which renders
/// as no-evidence — rather than being probed against a pair invented here.
pub struct OnlineEndpoints {
    bitcoin: EndpointPair,
    arbitrum: Option<EndpointPair>,
    overridden: bool,
}

impl OnlineEndpoints {
    /// Pair up already-parsed pairs.
    #[must_use]
    pub const fn new(
        bitcoin: EndpointPair,
        arbitrum: Option<EndpointPair>,
        overridden: bool,
    ) -> Self {
        Self {
            bitcoin,
            arbitrum,
            overridden,
        }
    }

    /// Every endpoint consulted, in disclosure order: the Bitcoin pair, then
    /// the Arbitrum pair when there is one.
    #[must_use]
    pub fn identities(&self) -> Vec<String> {
        let mut out = vec![
            self.bitcoin.first().url().to_owned(),
            self.bitcoin.second().url().to_owned(),
        ];
        if let Some(pair) = &self.arbitrum {
            out.push(pair.first().url().to_owned());
            out.push(pair.second().url().to_owned());
        }
        out
    }

    /// Whether this run departed from the pinned defaults — the overlay's
    /// disclosure datum (D64 §8 edit 5), never inferred at render time.
    #[must_use]
    pub const fn overridden(&self) -> bool {
        self.overridden
    }
}

/// Resolve `--online`'s endpoint pairs: U4's `[verify]` overrides if the
/// config carries them, A16/A17's pinned defaults otherwise.
///
/// An override **replaces the pair wholesale and must supply exactly two**
/// (the `[verify]` slots' own rule): a one-element override would leave a
/// must-agree pair agreeing with a default the user thought they had
/// replaced, and a three-element one has no defined reading. Both are
/// refused as `usage` (2), before any network work.
///
/// Returns `None` only when this network has no Bitcoin pair to consult,
/// which no shipped network does — the arm exists so a future one cannot
/// silently probe the wrong chain's endpoints.
///
/// # Errors
///
/// [`CliError::Usage`] — an override with the wrong number of entries, an
/// unparseable URL, or a pair that resolves to one origin (which would
/// report agreement between an endpoint and itself).
pub fn endpoints_from_config(
    config: &crate::config::Config,
    network: NetworkId,
) -> Result<Option<OnlineEndpoints>, CliError> {
    let bitcoin_default: Vec<String> = antseal_anchor::esplora::DEFAULT_ESPLORA_ENDPOINTS
        .iter()
        .map(|url| (*url).to_owned())
        .collect();
    let bitcoin_urls = config
        .verify_bitcoin_endpoints
        .as_ref()
        .unwrap_or(&bitcoin_default);
    let bitcoin = parse_pair(bitcoin_urls, "bitcoin_endpoints")?;

    let arbitrum_default: Option<Vec<String>> =
        antseal_anchor::arbitrum::endpoints::verify_rpcs(network)
            .map(|urls| urls.iter().map(|url| (*url).to_owned()).collect());
    let arbitrum = match config.verify_arbitrum_endpoints.as_ref() {
        Some(urls) => Some(parse_pair(urls, "arbitrum_endpoints")?),
        None => match &arbitrum_default {
            Some(urls) => Some(parse_pair(urls, "arbitrum_endpoints")?),
            None => None,
        },
    };

    let overridden =
        config.verify_bitcoin_endpoints.is_some() || config.verify_arbitrum_endpoints.is_some();
    Ok(Some(OnlineEndpoints::new(bitcoin, arbitrum, overridden)))
}

/// Parse exactly two URLs into a must-agree pair.
fn parse_pair(urls: &[String], key: &str) -> Result<EndpointPair, CliError> {
    let [first, second] = urls else {
        return Err(CliError::Usage {
            message: format!(
                "`[verify] {key}` must list exactly two endpoints (found {}): an override \
                 replaces the pinned pair wholesale, and a must-agree pair needs two \
                 independent sources",
                urls.len()
            ),
        });
    };
    let parse = |url: &str| {
        antseal_anchor::http::Endpoint::parse(
            url,
            antseal_anchor::TlsPolicy::RequiredExceptLoopback,
        )
        .map_err(|source| CliError::Usage {
            message: format!("`[verify] {key}`: {source}"),
        })
    };
    EndpointPair::new(parse(first)?, parse(second)?).map_err(|source| CliError::Usage {
        message: format!("`[verify] {key}`: {source}"),
    })
}

/// D64 §6.3's per-height class, from A16's agreement.
fn block_probe<T>(agreement: &Agreement<T>) -> BlockProbe {
    match agreement {
        Agreement::Agreed(_) => BlockProbe::Agreed,
        Agreement::Disagreed { .. } => BlockProbe::Disagreed,
        Agreement::Unavailable { failures } => {
            BlockProbe::Failed(failures.iter().map(probe_failure).collect())
        }
    }
}

/// A17's five outcomes, narrowed onto the overlay's four.
fn receipt_probe(confirmation: &ArbitrumConfirmation) -> ReceiptProbe {
    match confirmation.into_receipt_confirmation() {
        Some(agreed) => ReceiptProbe::Agreed(agreed),
        None => match confirmation {
            // `Lagging` is a disagreement about *when*, which is still a
            // disagreement: one endpoint has the transaction and the other
            // does not, so nothing was established.
            ArbitrumConfirmation::Disagreed { .. } | ArbitrumConfirmation::Lagging { .. } => {
                ReceiptProbe::Disagreed
            }
            ArbitrumConfirmation::Unavailable { failures } => {
                ReceiptProbe::Failed(failures.iter().map(probe_failure).collect())
            }
            // Unreachable: both of these project to `Some` above. Reported
            // as "not attempted" rather than panicking, because a renderer
            // must never be the thing that aborts a verification.
            ArbitrumConfirmation::Agreed(_) | ArbitrumConfirmation::Absent => {
                ReceiptProbe::NotAttempted
            }
        },
    }
}

/// Narrow one endpoint failure to the class core renders (D66).
///
/// `EndpointFailure` is `#[non_exhaustive]`, so this match needs a fallback
/// arm; it is `Transport`, which is the honest reading of *"the request did
/// not produce a usable answer and we cannot say more"* and is the class with
/// the weakest claim. A new arm upstream therefore degrades a label rather
/// than inventing a cause — which is the direction D66 wants.
fn probe_failure(failure: &EndpointFailure) -> EndpointProbeFailure {
    let class = match failure {
        EndpointFailure::Http(_) => ProbeFailureClass::Transport,
        EndpointFailure::Payload { .. } => ProbeFailureClass::Payload,
        EndpointFailure::WrongChain { .. } => ProbeFailureClass::WrongChain,
        _ => ProbeFailureClass::Transport,
    };
    EndpointProbeFailure {
        endpoint: failure.endpoint().to_owned(),
        class,
    }
}

// ---------------------------------------------------------------------------
// `--live` (S15's re-fetch, over the bundle's own embedded ciphertexts)
// ---------------------------------------------------------------------------

/// Re-fetch every blob this bundle embeds and byte-compare it — R11's live
/// check, driven from a `.sealproof` instead of from a vault record.
///
/// This is the **bundle-shaped adapter** `StorageRecord::new`'s own docs name
/// as M3's: `records_from_manifest` requires a ciphertext for *every* unit in
/// the manifest, and a partial reveal embeds only some, so the records are
/// built here over exactly the units the bundle carries. The recorded address
/// comes from the **signed manifest** and the bytes from the reveal section —
/// opposite sides of the bundle, which is what makes the comparison a
/// statement rather than a tautology.
///
/// # Errors
///
/// [`CliError::VerifyBundleRejected`] is **not** produced here: this runs
/// after verification, over a bundle that already passed. A bundle whose
/// manifest will not decode cannot reach this function.
///
/// [`CliError::Internal`] — the bundle passed verification and then failed to
/// yield its own manifest, which is an antseal bug rather than an input
/// problem.
pub async fn collect_live<B>(bundle: &BundleV1<'_>, backend: &B) -> Result<LiveInputs, CliError>
where
    B: StorageBackend,
{
    let manifest =
        Manifest::decode(bundle.manifest_bytes()).map_err(|source| CliError::Internal {
            detail: format!(
                "a verified bundle's manifest did not decode for the live check: {source}"
            ),
        })?;

    // Recorded addresses, by unit id — the signed side of the comparison.
    let recorded: BTreeMap<u64, (Address, UnitKindTag)> = manifest
        .body()
        .files()
        .iter()
        .flat_map(|file| file.units().iter())
        .map(|unit| {
            (
                unit.unit_id(),
                (Address::from(*unit.address()), unit.kind().into()),
            )
        })
        .collect();

    // Embedded ciphertexts, in bundle order — the revealed side.
    let embedded: Vec<(u64, &[u8])> = bundle
        .covered_reveals()
        .iter()
        .map(|reveal| (reveal.unit_id(), reveal.ciphertext().as_slice()))
        .chain(
            bundle
                .noncovered_reveals()
                .iter()
                .map(|reveal| (reveal.unit_id(), reveal.ciphertext().as_slice())),
        )
        .collect();

    let mut records: Vec<StorageRecord<'_>> = Vec::with_capacity(embedded.len() + 1);
    let mut subjects: Vec<String> = Vec::with_capacity(embedded.len() + 1);
    for (unit_id, ciphertext) in embedded {
        // A unit the manifest does not list cannot have a recorded address,
        // so there is nothing to fetch and nothing to compare. Skipped, not
        // guessed — and unreachable for a bundle that verified.
        let Some((address, kind)) = recorded.get(&unit_id) else {
            continue;
        };
        records.push(StorageRecord::new(
            LiveSubject::Unit {
                unit_id,
                kind: *kind,
            },
            *address,
            ciphertext,
        ));
        subjects.push(subject_label(LiveSubject::Unit {
            unit_id,
            kind: *kind,
        }));
    }

    // ── the encrypted-manifest row is NOT here, and the reason is a
    //    measured gap rather than a choice ──────────────────────────────
    //
    // R11's `LiveSubject::EncryptedManifest` exists and R20's *offline*
    // linkage layer checks exactly that blob — by rebuilding it with
    // `antseal_core::crypto::manifest_aead::recompute_manifest_blob`, which
    // is `pub(crate)` and therefore unreachable from this crate. There is no
    // other public route: `encrypt_manifest` draws a fresh random nonce, so
    // it cannot reproduce the blob the sealer uploaded.
    //
    // The consequence is bounded and stated rather than hidden: `--live`
    // proves persistence for every **unit** ciphertext the bundle embeds and
    // says nothing about the encrypted manifest. It is reported for a row;
    // the fix is one visibility change in a crate this lane may not write.
    // Guessing at the blob, or checking a different address, would be worse
    // than an honest absence.

    if records.is_empty() {
        // R11 refuses an empty check outright; the section reports
        // `NothingChecked` rather than a vacuous pass, which is exactly what
        // `LiveInputs::none()` renders.
        return Ok(LiveInputs::none());
    }

    let report = live_check(backend, &records)
        .await
        .map_err(|source| CliError::Internal {
            detail: format!("the live check could not be composed: {source}"),
        })?;

    Ok(LiveInputs::from_rows(
        report
            .rows
            .iter()
            .zip(subjects)
            .map(|(row, subject)| LiveBlobRow {
                subject,
                outcome: blob_outcome(&row.persistence.outcome),
            })
            .collect(),
    ))
}

/// One live row's subject label.
///
/// The label is the **host's**, by R21's own design: `LiveBlobRow::subject`
/// is documented as host-supplied because the subject vocabulary is R11's
/// [`LiveSubject`], which lives in `antseal-net` and cannot be named from
/// WASM-safe core. Nothing here is a frozen verdict sentence — the sentence
/// this label is dropped into is `wording::live_blob_*_line`'s.
fn subject_label(subject: LiveSubject) -> String {
    match subject {
        LiveSubject::Unit {
            unit_id,
            kind: UnitKindTag::Normal,
        } => format!("unit {unit_id}"),
        LiveSubject::Unit {
            unit_id,
            kind: UnitKindTag::RawMirror,
        } => format!("unit {unit_id} (raw mirror)"),
        LiveSubject::EncryptedManifest => "encrypted manifest".to_owned(),
    }
}

/// S15's per-blob outcome, projected onto core's WASM-safe four.
fn blob_outcome(outcome: &antseal_net::PersistenceOutcome) -> LiveBlobOutcome {
    match outcome {
        antseal_net::PersistenceOutcome::Identical => LiveBlobOutcome::Identical,
        antseal_net::PersistenceOutcome::Different { .. } => LiveBlobOutcome::Different,
        antseal_net::PersistenceOutcome::NotFound => LiveBlobOutcome::NotFound,
        antseal_net::PersistenceOutcome::FetchError { reason } => LiveBlobOutcome::FetchFailed {
            reason: reason.clone(),
        },
    }
}
