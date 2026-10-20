//! `config.toml` (U4): the plaintext operator-preference file beside the
//! vault AEAD (D42's beside-set, exactly), its strict v1 schema, and the
//! flag > config > default precedence.
//!
//! # Location and life cycle
//!
//! `<vault dir>/config.toml` (D42: one of exactly three beside-the-AEAD
//! files; operator *preferences* only — never secrets, never per-work
//! data). `init` writes the initial file ([`initial_config_text`], U11);
//! users edit it by hand; `vault export` embeds its raw bytes and import
//! restores them (D47 — the cross-test lives in `tests/config_file.rs`).
//! A missing file is the defaults; a malformed file is a hard, precise
//! [`CliError::MalformedConfig`] error on every command — a config that
//! cannot be read must never be silently ignored (its overrides would
//! silently vanish, which is the config-tamper failure mode D42 names).
//!
//! # The v1 schema
//!
//! ```toml
//! # Effective network when --network is absent (flag > config > default;
//! # built-in default: arbitrum-one).
//! default_network = "arbitrum-sepolia"
//!
//! # Per-network table. Chain ids, contract addresses, and payment RPC
//! # endpoints are antseal-net's pinned constants and are deliberately NOT
//! # configurable here — duplicating contract addresses in a hand-edited
//! # file is exactly the drift the S5 byte-equality test exists to
//! # prevent. `rpc_url` is REFUSED at load in every table (exit 17; U94,
//! # D180, D207): the payer dials the pinned public endpoint for
//! # arbitrum-one and arbitrum-sepolia, and the RPC_URL of the export
//! # ANTSEAL_DEVNET_ENV names for devnet — nothing reads an override.
//! [networks.arbitrum-one]
//!
//! # Storage-network bootstrap peers, arbitrum-one ONLY (D173 §2 R4). A
//! # present list REPLACES the vendored upstream list wholesale and is
//! # never merged with it (consumer: `crate::devnet_env::resolve_peers`).
//! # Validated at load through the one peer-set classifier: at least one
//! # entry, IP literals only, no repeat, no unspecified address, no port
//! # 0, no loopback — else exit 17 before dispatch, so before any
//! # passphrase. An EMPTY list is refused, not read as "the defaults".
//! # Under [networks.arbitrum-sepolia] or [networks.devnet] the key is a
//! # malformed config naming ANTSEAL_DEVNET_ENV, those networks' only
//! # peer source. (RFC 5737 documentation addresses, never routed.)
//! bootstrap = ["192.0.2.10:10000", "198.51.100.20:10000"]
//!
//! # RFC 3161 TSA list override (consumer: `seal`'s anchor stage, U26).
//! # A non-empty list REPLACES the built-in defaults wholesale; an empty
//! # or absent one uses them. Every entry is parsed by antseal-anchor's
//! # `Endpoint` at load (A50) under `TlsPolicy::Optional` — plain http is
//! # legitimate here, and required for DigiCert.
//! [anchors]
//! tsa_urls = ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]
//!
//! # OpenTimestamps calendar list (U44, D188) — ONE list in two roles
//! # (U52, U64): `seal`'s submit targets, and the only widening of A42's
//! # upgrade allowlist past the three pinned calendar domains
//! # (`status --upgrade` and the opportunistic pass). The `tsa_urls`
//! # conventions: a non-empty list replaces D54's four wholesale, an empty
//! # or absent one is the defaults, duplicates collapse
//! # (`antseal_anchor::ots::effective_calendars`, the one function both
//! # roles call). Validated at load under `TlsPolicy::Optional` — the
//! # submit path's own policy, since a calendar cannot forge a proof (D54
//! # §4) — so load and use cannot disagree.
//! ots_calendars = ["https://a.pool.opentimestamps.org", "https://b.pool.opentimestamps.org"]
//!
//! # The opportunistic upgrade pass's off switch (U60, D189; consumer:
//! # `crate::upgrade_hook::run_after_output`). Absent or `true` = the pass
//! # runs after every vault-holding command; `false` = it is skipped before
//! # any client, lock or poll exists. `status <work-id> --upgrade` is never
//! # affected. A bare boolean is the only accepted value.
//! opportunistic_upgrades = true
//!
//! # Online-endpoint overrides (consumer: U30's `verify --online`; the
//! # esplora pair also feeds `status --upgrade` and the opportunistic pass).
//! # Two independent must-agree sources per evidence class. These MUST be
//! # https (loopback IP literals are the only exemption) — their replies are
//! # unsigned, so the transport is their only integrity control and a
//! # plain-http override would let one on-path attacker forge both halves of
//! # a "must agree" pair (A49, decision D90 §6.6). `tsa_urls` and
//! # `ots_calendars` above are deliberately not subject to this: RFC 3161
//! # tokens are signed and nonce-bound, and a calendar cannot forge a proof.
//! # The esplora pair is exactly two endpoints at two origins, checked at
//! # load like the Arbitrum pair below (U101, D196 R3); delete the key, never
//! # empty it, to use the pinned pair.
//! [verify]
//! bitcoin_endpoints = ["https://a.example", "https://b.example"]
//!
//! # The Arbitrum receipt pair is PER NETWORK (U44, D188 R4; A17's Accept):
//! # exactly two endpoints at two origins, checked at load, replacing that
//! # network's pinned pair. There is no `[verify.devnet]` (refused: devnet's
//! # chain is a fresh Anvil per run, D55 §5).
//! [verify.arbitrum-one]
//! rpc_endpoints = ["https://c.example", "https://d.example"]
//! ```
//!
//! Unknown keys and unknown sections are **warnings** (forward
//! compatibility: a newer antseal's config must not crash an older one),
//! rendered once on stderr and never fatal. Invalid values for *recognized*
//! keys — an unknown network name, a non-string, a non-http(s) URL — are hard
//! errors: a recognized key the loader cannot honor must be loud (never a
//! silently-dropped override).
//!
//! **A recognized key is read only where it lives** (U100, D196 R1). Each of
//! the seven keys above has exactly one home (`KEY_HOMES`), and written in any
//! other table it is a malformed config naming the key, the table it was found
//! in, the line and its home — a warned override would quietly use the very
//! defaults it was written to replace (`rpc_endpoints` flat under `[verify]`
//! probes the pinned pair; a `default_network` written after a `[table]`
//! header, which TOML puts in that table, made the invocation arbitrum-one).
//! A `[networks.<id>]` or `[verify.<id>]` table's network name is judged
//! first, so an unknown network keeps its *not a known network* answer, and
//! these keep their own words: `bootstrap` under `[networks.arbitrum-sepolia]`
//! or `[networks.devnet]` (D173 §2 R4) names `ANTSEAL_DEVNET_ENV`, those
//! networks' only peer source; the retired `rpc_url` (U94, D180), a payment
//! slot no build ever read, is refused in every table, and outside
//! `[networks.<id>]` its words name the receipt check's pair too (D207); the
//! retired `arbitrum_endpoints` (U44, D188 R5) is refused in every table, its
//! pair having moved to `[verify.<network>] rpc_endpoints`; and
//! `[verify.devnet]` is refused whatever it holds: devnet has no RPC pair to
//! override. Every one of these is raised on the KEY, before the value is
//! parsed, so it never repeats the value and no shape of value can change the
//! answer.
//!
//! No refusal of a URL-list key — `tsa_urls`, `ots_calendars`,
//! `bitcoin_endpoints`, `rpc_endpoints` — repeats a value (U99, D195 R4): it
//! names the key, the line and the entry's position (the subset's too, U108),
//! because a URL can carry a credential in its userinfo, its query or a path
//! segment. The subset's own refusals repeat no value for any key.
//!
//! # The TOML subset, documented (and why it is hand-parsed)
//!
//! The workspace deliberately adds no TOML-crate dependency for one
//! small self-written file (lane rule: no new deps; a full TOML stack is
//! ~5 packages for a schema that is strings and string arrays). The v1
//! loader accepts a **documented strict subset** and hard-errors, with
//! the line number, on anything outside it:
//!
//! - blank lines and `#` comments;
//! - `[section]` / `[section.subsection]` headers (bare keys);
//! - `key = "basic string"` (no escape sequences — a backslash is a
//!   precise error) or `key = 'literal string'`;
//! - `key = ["a", "b"]` single-line arrays of strings;
//! - `key = true` / `key = false`, bare and lowercase (U60, D189 R1) — typed
//!   per key: a string or array key refuses a boolean with its own message;
//! - duplicate keys/sections are errors.
//!
//! Everything a v1 key needs is expressible; everything else — escapes,
//! multi-line strings, integers, dates, inline tables — is rejected with
//! a message naming the construct, so a hand-written full-TOML file
//! degrades into a precise complaint, never a misparse. That applies to a
//! **recognised** key's value only (D189 R3): an unknown key's value is
//! never parsed — the key is warned on by name, after its `[networks.<id>]`
//! or `[verify.<id>]` table name is judged — so a config written by a newer
//! antseal, whose values may use grammar this build lacks, still loads.
//! `docs/config.md` carries the user-facing statement of the same grammar.

use std::collections::BTreeMap;
use std::io::ErrorKind;
use std::net::SocketAddr;

use antseal_net::NetworkId;

use crate::cli::Network;
use crate::error::CliError;
use crate::vault::layout::{BesideFile, VaultLayout};
use crate::vault::session::read_vault_file;

/// Byte cap on the config file (D10 discipline; also the export-embed
/// cap — `vault/export.rs` references this same constant).
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// The parsed configuration (defaults = every field empty).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// `default_network` — the middle layer of the precedence rule.
    pub default_network: Option<NetworkId>,
    /// `[networks.arbitrum-one] bootstrap` — `arbitrum-one`'s storage
    /// bootstrap peers, which **replace** the vendored upstream list and
    /// are never merged with it (D173 §2 R4, R6). `None` is "no key": the
    /// resolver (`crate::devnet_env::resolve_peers`, the slot's consumer)
    /// then dials the vendored list. Never `Some(empty)`: an empty list is
    /// refused at load. Only `arbitrum-one` can carry one — the key is a
    /// malformed config under either other network — which is why this is
    /// a single slot named for it and not a per-network list.
    pub arbitrum_one_bootstrap: Option<Vec<SocketAddr>>,
    /// `[anchors] tsa_urls` — the effective TSA list for `seal`'s anchor
    /// stage (U26). `None` and `Some(empty)` both mean "the built-in
    /// defaults"; the collapse is
    /// [`antseal_anchor::effective_tsa_urls`](antseal_anchor::submit::AnchorEndpoints::from_config)'s,
    /// so one function decides it for every consumer.
    pub tsa_urls: Option<Vec<String>>,
    /// `[anchors] ots_calendars` (U44, D188) — the OpenTimestamps calendar
    /// list, read in **two roles from one source** (U52, U64): the calendars
    /// `seal`'s anchor stage submits to
    /// ([`AnchorStageConfig::from_config`](crate::seal_run::AnchorStageConfig::from_config)),
    /// and the hosts `status --upgrade` and the opportunistic pass admit beyond
    /// A42's three pinned calendar domains
    /// ([`UpgradeConfig::from_config`](crate::status::UpgradeConfig::from_config)).
    /// `None` and `Some(empty)` both mean D54's four defaults; the collapse —
    /// wholesale replacement and deduplication — is
    /// [`antseal_anchor::ots::effective_calendars`]'s, one function on both
    /// paths, so the two roles cannot read different lists.
    pub ots_calendars: Option<Vec<String>>,
    /// `[anchors] opportunistic_upgrades` (U60, D189 R2) — whether the
    /// opportunistic OpenTimestamps upgrade pass runs after a command that
    /// unlocked the vault. `None` is "no key", which means on; read it through
    /// [`Config::opportunistic_upgrades_enabled`]. Honoured by
    /// [`crate::upgrade_hook::run_after_output`] only — `status <work-id>
    /// --upgrade` is the user asking, and this key never suppresses it.
    pub opportunistic_upgrades: Option<bool>,
    /// `[verify] bitcoin_endpoints` — the esplora pair `verify --online`
    /// (U30), `status --upgrade` and the opportunistic pass confirm block
    /// headers against. Checked at load: exactly two endpoints at two origins
    /// ([`bitcoin_endpoint_pair`], the one validator its consumers call too —
    /// U101, D196 R3).
    pub verify_bitcoin_endpoints: Option<Vec<String>>,
    /// `[verify.arbitrum-one] rpc_endpoints` (U44, D188 R4) — arbitrum-one's
    /// Arbitrum receipt pair for `verify --online`, replacing A17's pinned
    /// pair wholesale. Checked at load: exactly two endpoints at two origins
    /// ([`rpc_endpoint_pair`]). Consumers read it through
    /// [`Config::verify_rpc_endpoints`].
    pub verify_arbitrum_one_rpc_endpoints: Option<Vec<String>>,
    /// `[verify.arbitrum-sepolia] rpc_endpoints` — as above, for
    /// arbitrum-sepolia. There is no devnet slot: devnet's chain is a fresh
    /// Anvil per run (D55 §5), and `[verify.devnet]` is refused at load.
    pub verify_arbitrum_sepolia_rpc_endpoints: Option<Vec<String>>,
    /// Unknown-key/section warnings (forward compat) — rendered once on
    /// stderr by the entry point, never fatal, never on stdout.
    pub warnings: Vec<String>,
}

impl Config {
    /// `network`'s `[verify.<network>] rpc_endpoints` override, if the file
    /// set one (U44, D188 R6). The match has no wildcard arm on purpose: a
    /// network added later must decide here whether it has a pair, rather
    /// than inherit another network's. `Devnet` has none.
    #[must_use]
    pub fn verify_rpc_endpoints(&self, network: NetworkId) -> Option<&[String]> {
        match network {
            NetworkId::ArbitrumOne => self.verify_arbitrum_one_rpc_endpoints.as_deref(),
            NetworkId::ArbitrumSepolia => self.verify_arbitrum_sepolia_rpc_endpoints.as_deref(),
            NetworkId::Devnet => None,
        }
    }

    /// Whether the opportunistic upgrade pass runs: the file's
    /// `[anchors] opportunistic_upgrades`, or `true` when the key is absent —
    /// so a config without it, and [`Config::default`], keep the pass (U60,
    /// D189 R2).
    #[must_use]
    pub fn opportunistic_upgrades_enabled(&self) -> bool {
        self.opportunistic_upgrades.unwrap_or(true)
    }

    /// The slot `[verify.<network>] rpc_endpoints` loads into — `None` for the
    /// network with no pair to override (devnet), so the loader and
    /// [`Config::verify_rpc_endpoints`] cannot disagree about which exist.
    fn verify_rpc_slot(&mut self, network: NetworkId) -> Option<&mut Option<Vec<String>>> {
        match network {
            NetworkId::ArbitrumOne => Some(&mut self.verify_arbitrum_one_rpc_endpoints),
            NetworkId::ArbitrumSepolia => Some(&mut self.verify_arbitrum_sepolia_rpc_endpoints),
            NetworkId::Devnet => None,
        }
    }
}

/// The effective network: flag > config > built-in `arbitrum-one`
/// (MVP scope decision 4). The flag layer only exists because
/// `--network` parses as `Option` — a clap-level default would make an
/// explicit `--network arbitrum-one` indistinguishable from absence and
/// the precedence untestable.
#[must_use]
pub fn effective_network(flag: Option<Network>, config: &Config) -> NetworkId {
    match flag {
        Some(network) => network.into(),
        None => config.default_network.unwrap_or_default(),
    }
}

impl From<Network> for NetworkId {
    fn from(network: Network) -> Self {
        match network {
            Network::ArbitrumOne => NetworkId::ArbitrumOne,
            Network::ArbitrumSepolia => NetworkId::ArbitrumSepolia,
            Network::Devnet => NetworkId::Devnet,
        }
    }
}

/// Load the config beside the resolved vault directory. Missing file (or
/// no resolvable vault directory at all — a homeless `verify`-only
/// machine) ⇒ defaults; malformed content ⇒ the typed hard error.
///
/// # Errors
///
/// [`CliError::MalformedConfig`] with the path, line, and problem;
/// [`CliError::Io`] for unreadable-but-present files.
pub fn load() -> Result<Config, CliError> {
    let Ok(layout) = VaultLayout::resolve() else {
        // No home and no ANTSEAL_DIR: nowhere a config could live.
        // Vault-needing commands will fail on their own terms later.
        return Ok(Config::default());
    };
    load_from(&layout)
}

/// Load from an explicit layout (tests; import's post-checks).
///
/// # Errors
///
/// As [`load`].
pub fn load_from(layout: &VaultLayout) -> Result<Config, CliError> {
    let path = layout.beside_path(BesideFile::Config);
    let bytes = match read_vault_file(&path, MAX_CONFIG_BYTES + 1) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(Config::default()),
        Err(source) => {
            return Err(CliError::Io {
                context: format!("reading {}", path.display()),
                source,
            });
        }
    };
    let malformed = |line: usize, detail: String| CliError::MalformedConfig {
        path: path.clone(),
        line,
        detail,
    };
    if bytes.len() > MAX_CONFIG_BYTES {
        return Err(malformed(
            0,
            format!("file exceeds the {} KiB cap", MAX_CONFIG_BYTES / 1024),
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| malformed(0, "file is not valid UTF-8".to_owned()))?;
    parse(text).map_err(|e| malformed(e.line, e.detail))
}

/// The initial config `init` writes (U11 consumes; keep in sync with the
/// schema doc above and docs/config.md).
#[must_use]
pub fn initial_config_text(network: NetworkId) -> String {
    format!(
        "# antseal configuration — operator preferences only (docs/config.md).\n\
         # Precedence: --network flag > this file > built-in default (arbitrum-one).\n\
         default_network = \"{network}\"\n"
    )
}

/// A parse failure: the line (1-based; 0 = whole file) and the problem.
#[derive(Debug, PartialEq, Eq)]
pub struct ConfigParseError {
    /// 1-based line number (0 for whole-file problems).
    pub line: usize,
    /// What is wrong, precisely, without echoing unrelated content.
    pub detail: String,
}

/// Parse config text against the documented v1 subset + schema.
///
/// # Errors
///
/// [`ConfigParseError`] naming the line and the precise problem.
pub fn parse(text: &str) -> Result<Config, ConfigParseError> {
    let mut config = Config::default();
    let mut section: Vec<String> = Vec::new(); // current [a.b] path
    let mut seen_keys: BTreeMap<String, usize> = BTreeMap::new();

    for (index, raw_line) in text.lines().enumerate() {
        let line_no = index + 1;
        let err = |detail: String| ConfigParseError {
            line: line_no,
            detail,
        };
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }

        // Section header.
        if let Some(rest) = line.strip_prefix('[') {
            let inner = rest
                .strip_suffix(']')
                .ok_or_else(|| err("section header is missing its closing `]`".to_owned()))?
                .trim();
            if inner.is_empty() {
                return Err(err("empty section name".to_owned()));
            }
            if inner.starts_with('[') {
                return Err(err(
                    "array-of-tables `[[…]]` is outside the antseal config subset".to_owned(),
                ));
            }
            let parts: Vec<String> = inner.split('.').map(|p| p.trim().to_owned()).collect();
            if parts.iter().any(String::is_empty) {
                return Err(err("section name has an empty component".to_owned()));
            }
            for part in &parts {
                if !is_bare_key(part) {
                    return Err(err(format!(
                        "section component `{part}` is not a bare key \
                         (a-z, 0-9, `-`, `_` only in this config)"
                    )));
                }
            }
            section = parts;
            let key = section.join(".");
            if let Some(first) = seen_keys.insert(format!("[{key}]"), line_no) {
                return Err(err(format!(
                    "section `[{key}]` already defined on line {first}"
                )));
            }
            continue;
        }

        // key = value.
        let Some((key_raw, value_raw)) = line.split_once('=') else {
            return Err(err(
                "expected `key = value` or a `[section]` header".to_owned()
            ));
        };
        let key = key_raw.trim();
        if !is_bare_key(key) {
            return Err(err(format!(
                "key `{key}` is not a bare key (a-z, 0-9, `-`, `_` only in this config)"
            )));
        }
        let full_key = if section.is_empty() {
            key.to_owned()
        } else {
            format!("{}.{key}", section.join("."))
        };
        if let Some(first) = seen_keys.insert(full_key.clone(), line_no) {
            return Err(err(format!("key `{full_key}` already set on line {first}")));
        }
        // U94 (D180): refused on the KEY, before the value is parsed, so no
        // shape of value can change the answer or reach the error (see
        // `rpc_url_refusal`).
        if let [family, network_name] = section.as_slice()
            && family == "networks"
            && key == "rpc_url"
        {
            return Err(err(rpc_url_refusal(network_name)));
        }
        // U44 (D188 R5): the flat `[verify] arbitrum_endpoints` is retired the
        // same way and for the same reason — refused on the KEY, so no shape
        // of its value can reach the error (see `arbitrum_endpoints_refusal`).
        if let [family] = section.as_slice()
            && family == "verify"
            && key == "arbitrum_endpoints"
        {
            return Err(err(arbitrum_endpoints_refusal()));
        }

        // The value goes to `apply` RAW: each recognised key parses it there,
        // so a key can refuse it in its own words (`[verify.<network>]
        // rpc_endpoints`, D188 R5), and an unknown key's value is never parsed
        // at all (D189 R3).
        apply(
            &mut config,
            &section,
            key,
            &full_key,
            value_raw.trim(),
            line_no,
        )?;
    }
    Ok(config)
}

/// A parsed subset value.
enum Value {
    Str(String),
    Array(Vec<String>),
    /// A bare lowercase `true` / `false` (U60, D189 R1). Typed per key: every
    /// string or array key refuses one with its own message.
    Bool(bool),
}

/// A value the subset refuses: what is wrong and, inside a one-line array,
/// which entry (U108, D195 §2 R4). The key is not known here, so the caller
/// names it in front ([`SubsetError::for_key`]); nothing here holds the value,
/// which can carry a credential (U99, D195 R4).
struct SubsetError {
    /// The refused entry's position, counted from 0 like every other entry
    /// refusal's — or `None` when the refusal is about the whole value: an
    /// unquoted bare value is not a list and has no entry to name.
    entry: Option<usize>,
    /// What is wrong, in words that never repeat the value.
    reason: String,
}

impl SubsetError {
    /// A refusal of the whole value.
    fn whole(reason: impl Into<String>) -> Self {
        Self {
            entry: None,
            reason: reason.into(),
        }
    }

    /// A refusal of the array entry at `index`.
    fn at_entry(index: usize, reason: impl Into<String>) -> Self {
        Self {
            entry: Some(index),
            reason: reason.into(),
        }
    }

    /// The refusal in the house form, after the name of the key it belongs to:
    /// "`{key}` entry {N}: …" for an entry, "`{key}`: …" for a whole value.
    fn for_key(&self, key: &str) -> String {
        match self.entry {
            Some(index) => format!("`{key}` entry {index}: {}", self.reason),
            None => format!("`{key}`: {}", self.reason),
        }
    }
}

fn strip_comment(line: &str) -> &str {
    // A `#` inside a quoted string must survive; scan with quote state.
    let mut in_quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match (c, in_quote) {
            ('"' | '\'', None) => in_quote = Some(c),
            (q, Some(open)) if q == open => in_quote = None,
            ('#', None) => return &line[..i],
            _ => {}
        }
    }
    line
}

fn is_bare_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
}

fn parse_value(raw: &str) -> Result<Value, SubsetError> {
    // D189 R1: exactly TOML's two spellings, bare and lowercase. `True`,
    // `"false"` and `off` are not booleans here; a key that wants one says so
    // in its own words.
    match raw {
        "true" => return Ok(Value::Bool(true)),
        "false" => return Ok(Value::Bool(false)),
        _ => {}
    }
    if raw.starts_with('[') {
        let inner = raw
            .strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .ok_or_else(|| {
                SubsetError::whole("array value must open and close on one line in this config")
            })?;
        let mut items = Vec::new();
        let trimmed = inner.trim();
        if !trimmed.is_empty() {
            // U108 (D195 §2 R4): every refusal here is about ONE entry, so it
            // names that entry's position. A refusal from inside a nested
            // array takes the outer position: that is the entry a user can
            // count to on the line.
            for (index, part) in split_array_items(trimmed)?.into_iter().enumerate() {
                let piece = part.trim();
                let entry = parse_value(piece).map_err(|refusal| {
                    // U118: the splitter cuts a nested array of two or more
                    // elements at its own commas, so its first piece fails as
                    // an array that does not close on one line, which is
                    // false. A piece that opens an array is a nested array.
                    let reason = if piece.starts_with('[') {
                        NESTED_ARRAY_REASON.to_owned()
                    } else {
                        refusal.reason
                    };
                    SubsetError::at_entry(index, reason)
                })?;
                match entry {
                    Value::Str(s) => items.push(s),
                    Value::Array(_) => {
                        return Err(SubsetError::at_entry(index, NESTED_ARRAY_REASON));
                    }
                    Value::Bool(_) => {
                        return Err(SubsetError::at_entry(
                            index,
                            "array entries must be quoted strings: a boolean inside an array \
                             is outside the config subset",
                        ));
                    }
                }
            }
        }
        return Ok(Value::Array(items));
    }
    parse_string(raw)
        .map(Value::Str)
        .map_err(SubsetError::whole)
}

/// Split a single-line array body on top-level commas (commas inside
/// quotes survive). A quote still open at the end is refused as part of the
/// entry it opened in, by that entry's position (U108).
fn split_array_items(inner: &str) -> Result<Vec<&str>, SubsetError> {
    let mut items = Vec::new();
    let mut start = 0usize;
    let mut in_quote: Option<char> = None;
    for (i, c) in inner.char_indices() {
        match (c, in_quote) {
            ('"' | '\'', None) => in_quote = Some(c),
            (q, Some(open)) if q == open => in_quote = None,
            (',', None) => {
                items.push(&inner[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    if in_quote.is_some() {
        // Every comma after the quote opened was inside it, so the quote
        // opened in the entry after the last split: entry `items.len()`.
        return Err(SubsetError::at_entry(
            items.len(),
            "unterminated string inside array",
        ));
    }
    let tail = &inner[start..];
    if !tail.trim().is_empty() {
        items.push(tail);
    }
    Ok(items)
}

fn parse_string(raw: &str) -> Result<String, String> {
    for quote in ['"', '\''] {
        if let Some(rest) = raw.strip_prefix(quote) {
            let inner = rest
                .strip_suffix(quote)
                .ok_or_else(|| format!("unterminated {quote}-quoted string"))?;
            if inner.contains(quote) {
                return Err(format!("stray {quote} inside a {quote}-quoted string"));
            }
            if quote == '"' && inner.contains('\\') {
                return Err("escape sequences are outside the antseal config subset \
                     (use a literal '…' string)"
                    .to_owned());
            }
            return Ok(inner.to_owned());
        }
    }
    // U99 (D195 R4): the one subset message that met its input never repeats
    // it, for every key — a URL-list entry written without quotes can carry a
    // credential, and nothing here knows which key the value belongs to.
    // `apply` names the key in front of it, `parse_value` the entry (U108).
    Err(format!(
        "the value is not a quoted string, a [\"…\"] array, or a bare true/false \
         (integers, dates, and inline tables are outside the antseal config subset)\
         {SUBSET_VALUE_NOT_REPEATED}"
    ))
}

fn http_url_shape(value: &str) -> bool {
    (value.starts_with("https://") && value.len() > "https://".len())
        || (value.starts_with("http://") && value.len() > "http://".len())
}

/// Parse and validate `[networks.arbitrum-one] bootstrap` (D173 §2 R4).
///
/// Every entry must be an IP-literal `ip:port` socket address — a hostname
/// such as `example.org:10000` is refused, because nothing on the pinned
/// storage client path resolves names — and the entries must form a set
/// `arbitrum-one` can dial, which is the one classifier's decision (D173 §2
/// R8, [`antseal_net::peer_locality`]): no repeat, no unspecified address,
/// no port 0, and no loopback peer, so neither an all-loopback nor a mixed
/// list loads. The classifier names indices, never addresses; the shape
/// refusal names the entry, which is the user's own plaintext config.
fn parse_bootstrap_override(items: &[String]) -> Result<Vec<SocketAddr>, String> {
    if items.is_empty() {
        return Err(
            "`bootstrap` must list at least one \"ip:port\" peer: an empty list is \
                    refused rather than read as the built-in list — delete the key to use \
                    the built-in list"
                .to_owned(),
        );
    }
    let mut peers = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let peer: SocketAddr = item.parse().map_err(|_| {
            format!(
                "`bootstrap` entry {index} (`{item}`) is not an IP-literal \"ip:port\" socket \
                 address; a hostname is refused because nothing on the storage client path \
                 resolves names, and a port is required"
            )
        })?;
        peers.push(peer);
    }
    antseal_net::peer_locality(NetworkId::ArbitrumOne, &peers)
        .map_err(|refusal| format!("`bootstrap`: {refusal}"))?;
    Ok(peers)
}

/// The refusal for `rpc_url` under `[networks.<network_name>]` — **U94's
/// ruling (D180 U94 R1–R3): the key is retired, and refused at load.**
///
/// U4 reserved it as a payment-RPC override slot for S6, and no build ever
/// read it: the payer dials the pinned public endpoint for `arbitrum-one` and
/// `arbitrum-sepolia`, and the export's `RPC_URL` for `devnet`, whatever this
/// file says. Accepting the key told a user their endpoint was used when it
/// was not, so it is a malformed config (17) rather than a warning — a warning
/// would print while `seal` paid through the very endpoint the user had
/// configured away from, and a silently dropped override is worse than a loud
/// stop (`CliError::MalformedConfig`'s own rule).
///
/// Wiring it was measured **buildable** at the pin and refused, not ruled out
/// (D180): a refusal is reversible — a later wiring is additive, and an older
/// binary that cannot honour the key keeps failing closed — while wiring now
/// would commit the file to an input that usually carries an API key, on error
/// paths that print the URL a transport failed on, for a privacy gain the
/// storing peers already void (they see the paying transactions either way).
///
/// The section name is validated **first** (R2), so `[networks.ropsten]`
/// keeps its *not a known network* answer. The text names the key and the
/// table — the line rides on [`ConfigParseError::line`] — and never the value;
/// the caller raises it before the value is parsed, so no shape of value can
/// change the answer. (The subset's own *not a quoted string* error repeated
/// the raw value it rejected until U99 made it value-free, D195 R4.)
fn rpc_url_refusal(network_name: &str) -> String {
    match network_name.parse::<NetworkId>() {
        Err(_) => unknown_network("networks", network_name),
        Ok(id) => format!(
            "`rpc_url` under [networks.{id}] is refused: antseal reads no payment-RPC \
             override — arbitrum-one and arbitrum-sepolia pay through their pinned public \
             RPC endpoints, and devnet through the RPC_URL of the export ANTSEAL_DEVNET_ENV \
             names. Delete the line; its value is not repeated here, because an RPC URL \
             often carries an API key"
        ),
    }
}

/// The refusal for the flat `[verify] arbitrum_endpoints` — **U44's ruling
/// (D188 R5): the key is retired, and refused at load.**
///
/// One flat list could not hold A17's per-network pairs, so the Arbitrum
/// receipt pair moved to `[verify.arbitrum-one]` and
/// `[verify.arbitrum-sepolia]` (`rpc_endpoints`). D55 §6 planned to *warn* on
/// the old key, on the premise that nothing consumed it; U30 had wired it to
/// `verify --online` by then, so a warning would leave `verify --online`
/// probing the pinned pair the user had configured away from — D180's reason
/// for refusing `rpc_url`, one table over. The text names the key, the table
/// and the replacement tables — the line rides on [`ConfigParseError::line`]
/// — and never the value; the caller raises it before the value is parsed.
fn arbitrum_endpoints_refusal() -> String {
    "`arbitrum_endpoints` under [verify] is retired: the Arbitrum RPC pair is set per \
     network — write `rpc_endpoints` under [verify.arbitrum-one] or \
     [verify.arbitrum-sepolia] instead. Its value is not repeated here, because an RPC \
     URL often carries an API key"
        .to_owned()
}

/// The answer for a `[<family>.<network_name>]` table whose network is not
/// one of the three — the same words for `[networks.*]` and `[verify.*]`.
fn unknown_network(family: &str, network_name: &str) -> String {
    format!(
        "`[{family}.{network_name}]` is not a known network (valid: arbitrum-one, \
         arbitrum-sepolia, devnet)"
    )
}

/// The refusal for any key under `[verify.devnet]` (U44, D188 R4).
fn devnet_verify_refusal() -> String {
    "`[verify.devnet]` is refused: devnet has no RPC pair to override — its chain is a \
     fresh Anvil per run (D55 §5), so `verify --online` probes no Arbitrum endpoint on \
     devnet. Delete the table"
        .to_owned()
}

/// `[verify.<network_name>]`'s table-name check (U44, D188 R4), run before
/// any key in the table is read: an unknown network keeps the
/// `[networks.<id>]` answer, and `devnet` is refused whatever the key,
/// because there is nothing on devnet for the table to configure.
fn verify_table_network(network_name: &str) -> Result<NetworkId, String> {
    let id: NetworkId = network_name
        .parse()
        .map_err(|_| unknown_network("verify", network_name))?;
    match id {
        NetworkId::Devnet => Err(devnet_verify_refusal()),
        NetworkId::ArbitrumOne | NetworkId::ArbitrumSepolia => Ok(id),
    }
}

/// Where a key this build knows lives (U100, D196 R1).
#[derive(Clone, Copy)]
enum Home {
    /// Before the first `[table]` header.
    TopLevel,
    /// `[networks.arbitrum-one]` (D173 §2 R4).
    NetworksArbitrumOne,
    /// `[anchors]`.
    Anchors,
    /// `[verify]`.
    Verify,
    /// `[verify.arbitrum-one]` or `[verify.arbitrum-sepolia]` (D188 R4).
    VerifyNetwork,
    /// Nowhere: the flat `arbitrum_endpoints`, retired into
    /// `[verify.<network>] rpc_endpoints` and refused in every table (D188 R5).
    RetiredIntoRpcEndpoints,
    /// Nowhere: `rpc_url`, the payment-RPC override slot no build ever read
    /// (U94, D180), refused in every table (D207). Under `[networks.<id>]`
    /// `parse` refuses it first, in D180's words; every other table reaches
    /// this row, whose words name the receipt check's pair as well.
    RetiredPaymentRpc,
}

/// Every key this build knows: each key it reads, with its one home (U100,
/// D196 R1), and the two retired keys, refused in every table (D188 R5,
/// D207). It is the table `apply`'s three fall-through arms consult before
/// they warn, so a KNOWN key written in a foreign table is refused by name
/// instead of being warned on as if it were unknown. A key added to `apply`
/// must be added here too, or a misplaced copy of it only warns.
///
/// Why refuse rather than warn (D188 R5's ground, extended to every key): a
/// warned override quietly uses the very defaults it was written to replace —
/// measured, all seven keys and the retired one misplaced silently, and a
/// `default_network` written after an `[anchors]` header made the invocation
/// arbitrum-one. Unknown keys still warn (D189 R3's forward-compatibility
/// promise). `rpc_url` is refused in every table (D207): `parse` refuses it
/// under any `[networks.<id>]` first, in D180's words, and every other table
/// reaches its row here.
const KEY_HOMES: &[(&str, Home)] = &[
    ("default_network", Home::TopLevel),
    ("bootstrap", Home::NetworksArbitrumOne),
    ("tsa_urls", Home::Anchors),
    ("ots_calendars", Home::Anchors),
    ("opportunistic_upgrades", Home::Anchors),
    ("bitcoin_endpoints", Home::Verify),
    ("rpc_endpoints", Home::VerifyNetwork),
    ("arbitrum_endpoints", Home::RetiredIntoRpcEndpoints),
    ("rpc_url", Home::RetiredPaymentRpc),
];

/// The refusal for a key [`KEY_HOMES`] knows, found in `section`, which is not
/// its home — or `None` for a key this build does not know, which warns
/// (D189 R3). Raised on the KEY, before the value is parsed, so it names the
/// key, the table it was found in and its home (the line rides on
/// [`ConfigParseError::line`]) and never the value. The callers have already
/// judged a `[networks.<id>]` or `[verify.<id>]` table's network name, so an
/// unknown network keeps its own answer.
fn misplaced_key_refusal(key: &str, section: &[String]) -> Option<String> {
    let (_, home) = KEY_HOMES.iter().find(|(known, _)| *known == key)?;
    let found = if section.is_empty() {
        "at the top level".to_owned()
    } else {
        format!("under [{}]", section.join("."))
    };
    let belongs = match home {
        Home::TopLevel => "at the top of the file, before the first [table] header",
        Home::NetworksArbitrumOne => "under [networks.arbitrum-one]",
        Home::Anchors => "under [anchors]",
        Home::Verify => "under [verify]",
        Home::VerifyNetwork => "under [verify.arbitrum-one] or [verify.arbitrum-sepolia]",
        Home::RetiredIntoRpcEndpoints => {
            // Under a per-network table the user is one key name away from
            // the right line, so the text says so (D196 R2).
            let instead = match section {
                [family, _] if family == "verify" => "in this table",
                _ => "under [verify.arbitrum-one] or [verify.arbitrum-sepolia]",
            };
            return Some(format!(
                "`{key}` {found} is retired: the Arbitrum RPC pair is set per network — \
                 write `rpc_endpoints` {instead} instead. Its value is not repeated here, \
                 because an RPC URL often carries an API key"
            ));
        }
        Home::RetiredPaymentRpc => {
            // D207 R1: two facts, because `rpc_endpoints` does not replace this
            // slot — antseal reads no payment-RPC override at all, and the only
            // RPC setting this file carries, the receipt check's, takes two
            // URLs. Under a per-network table that pair belongs in this table.
            let pair = match section {
                [family, _] if family == "verify" => {
                    "the receipt check takes a pair — write `rpc_endpoints` with two endpoint \
                     URLs in this table instead"
                }
                _ => {
                    "the receipt check's pair is `rpc_endpoints` under [verify.arbitrum-one] or \
                     [verify.arbitrum-sepolia]"
                }
            };
            return Some(format!(
                "`{key}` {found} is retired: antseal reads no payment-RPC override, and {pair}. \
                 Its value is not repeated here, because an RPC URL often carries an API key"
            ));
        }
    };
    Some(format!(
        "`{key}` is not read {found}: it belongs {belongs} — move the line there. Its value \
         is not repeated here"
    ))
}

/// What every `rpc_endpoints` refusal says in place of the value (D188 R5).
const RPC_VALUE_NOT_REPEATED: &str =
    "the value is not repeated here, because an RPC URL often carries an API key";

/// What every other URL-list refusal says in place of the value (U99, D195
/// R4): `tsa_urls`, `ots_calendars` and `bitcoin_endpoints` name the key, the
/// line and the entry's position, never the entry — userinfo, a query or a
/// path segment can each carry a credential, and a refusal's text ends up in
/// terminals, logs and `--json` output.
const URL_VALUE_NOT_REPEATED: &str =
    "the value is not repeated here, because a URL can carry a credential";

/// The subset's own withheld-value clause (U99, D195 R4), which ends the one
/// subset refusal that met its input: `parse_string`'s message is built from
/// it, and `rpc_endpoints_value` strips it, because that key's sentence ends
/// with its own form of the clause — so every refusal says it once (U111).
const SUBSET_VALUE_NOT_REPEATED: &str = "; it is not repeated here";

/// Why an array entry that is itself an array is refused (U118): one reason
/// for a nested array of one element and of several, under every key.
const NESTED_ARRAY_REASON: &str = "nested arrays are outside the config subset";

/// The `rpc_endpoints` value as a list, parsed **without ever repeating it**
/// (D188 R5): every failure here is one sentence naming the table and the
/// accepted shape — and, when the subset refused one entry, that entry's
/// position and the subset's reason for it (U108, U111; D195 §2 R4). The
/// sentence ends with this key's own withheld-value clause, so the reason
/// carries the subset's without its `SUBSET_VALUE_NOT_REPEATED` tail.
fn rpc_endpoints_value(raw: &str, network: NetworkId) -> Result<Vec<String>, String> {
    let entry = match parse_value(raw) {
        Ok(Value::Array(items)) => return Ok(items),
        Err(SubsetError {
            entry: Some(index),
            reason,
        }) => {
            let reason = reason
                .strip_suffix(SUBSET_VALUE_NOT_REPEATED)
                .unwrap_or(&reason);
            format!(", and entry {index} is not one: {reason}")
        }
        Ok(Value::Str(_) | Value::Bool(_)) | Err(SubsetError { entry: None, .. }) => String::new(),
    };
    Err(format!(
        "`rpc_endpoints` under [verify.{network}] takes a one-line array of exactly two \
         quoted endpoint URLs{entry}; {RPC_VALUE_NOT_REPEATED}"
    ))
}

/// `[verify.<network>] rpc_endpoints`' one validator (U44, D188 R4, R5) — the
/// load-time check AND the pair `verify --online` is built with, so the two
/// cannot disagree (A50's one-implementation rule, as for the URL check in
/// [`apply`]).
///
/// Exactly two entries: one endpoint cannot be a must-agree pair, and a third
/// has no defined reading (U44). Each is parsed by the substrate's own
/// [`antseal_anchor::Endpoint::parse`] under
/// [`antseal_anchor::TlsPolicy::RequiredExceptLoopback`] — the reply is
/// unsigned, so the transport is its only integrity control (A49) — and the
/// two must be different origins by the substrate's own
/// [`antseal_anchor::agree::EndpointPair::new`].
///
/// Every refusal names the key, the table and the entry **index**, never a URL
/// and never an origin: an Arbitrum RPC endpoint that answers
/// `eth_getTransactionReceipt` commonly carries an API key in its URL (D55 §2
/// round 2), and error text ends up in terminals, logs and `--json` output
/// (D180 §2).
///
/// # Errors
///
/// The refusal text, for the caller to place: a [`ConfigParseError`] at load,
/// a usage error at use.
pub(crate) fn rpc_endpoint_pair(
    items: &[String],
    network: NetworkId,
) -> Result<antseal_anchor::agree::EndpointPair, String> {
    must_agree_pair(
        items,
        &format!("`rpc_endpoints` under [verify.{network}]"),
        "that network's pinned pair",
        RPC_VALUE_NOT_REPEATED,
    )
}

/// `[verify] bitcoin_endpoints`' one validator (U101, D196 R3) — the
/// load-time check AND the pair `verify --online`, `status --upgrade` and the
/// opportunistic upgrade pass build, so load and use cannot disagree (A50's
/// one-implementation rule, as for [`rpc_endpoint_pair`], whose three rules it
/// shares). Before U101 the list was checked only at use, by two
/// implementations with two texts, so a one- or three-entry list loaded and
/// then silently disabled the opportunistic pass.
///
/// One rule more than the RPC pair (D196 R3, as widened): no entry may carry
/// a query or a fragment, because esplora requests append `/{path}` to the
/// whole configured URL (antseal-anchor `esplora.rs`'s `join`). A query would
/// swallow every request's path — `https://h/api?key=K` asks for
/// `…?key=K/block-height/H`, which the derived URL's re-parse still accepts —
/// and a fragment would drop it, since the URI parser discards everything
/// after `#`. Not applied to `rpc_endpoints`: an RPC URL is used as written,
/// and a query there is legitimate.
///
/// Every refusal names the key, the table and the count or the entry's
/// position, never a URL and never an origin (U99, D195 R4). An empty list is
/// refused (`found 0`) rather than read as the built-in pair: deleting the key
/// is how a user gets that back.
///
/// # Errors
///
/// The refusal text, for the caller to place: a [`ConfigParseError`] at load,
/// a usage error at use — where only a [`Config`] the loader did not build can
/// reach it.
pub(crate) fn bitcoin_endpoint_pair(
    items: &[String],
) -> Result<antseal_anchor::agree::EndpointPair, String> {
    const LABEL: &str = "`bitcoin_endpoints` under [verify]";
    let pair = must_agree_pair(items, LABEL, "the pinned pair", URL_VALUE_NOT_REPEATED)?;
    // Both entries parsed above, so `?` and `#` can only open a query or a
    // fragment here — never a path byte, a host or userinfo.
    if let Some(index) = items.iter().position(|url| url.contains(['?', '#'])) {
        return Err(format!(
            "{LABEL}: entry {index} carries a query or a fragment (`?` or `#`), and antseal \
             appends request paths to it, so every request would lose its path; \
             {URL_VALUE_NOT_REPEATED}"
        ));
    }
    Ok(pair)
}

/// The rules both `[verify]` overrides obey: exactly two entries, each the
/// substrate's own endpoint under `RequiredExceptLoopback`, at two origins.
/// `label` names the key and its table, `pinned` the pair an override
/// replaces, and `not_repeated` is said in place of the value — so no refusal
/// here carries a URL or an origin.
fn must_agree_pair(
    items: &[String],
    label: &str,
    pinned: &str,
    not_repeated: &str,
) -> Result<antseal_anchor::agree::EndpointPair, String> {
    let [first, second] = items else {
        return Err(format!(
            "{label} must list exactly two endpoints (found {}): an override replaces {pinned} \
             wholesale, and a must-agree pair needs two independent sources",
            items.len()
        ));
    };
    let parse = |index: usize, url: &str| {
        antseal_anchor::Endpoint::parse(url, antseal_anchor::TlsPolicy::RequiredExceptLoopback)
            .map_err(|refusal| {
                format!(
                    "{label}: entry {index} {}; {not_repeated}",
                    endpoint_refusal_without_url(&refusal)
                )
            })
    };
    antseal_anchor::agree::EndpointPair::new(parse(0, first)?, parse(1, second)?).map_err(|_| {
        format!(
            "{label}: entries 0 and 1 are one origin, and a must-agree pair of one endpoint \
             agrees with itself and proves nothing; {not_repeated}"
        )
    })
}

/// An [`antseal_anchor::EndpointError`], said without the URL it carries.
fn endpoint_refusal_without_url(refusal: &antseal_anchor::EndpointError) -> String {
    match refusal {
        antseal_anchor::EndpointError::Invalid { reason, .. } => {
            format!("is not a usable endpoint URL ({reason})")
        }
        antseal_anchor::EndpointError::TlsRequired { .. } => {
            "must be https (only a loopback IP literal is exempt)".to_owned()
        }
        // `#[non_exhaustive]`: a class added upstream is still said without
        // its URL.
        _ => "is not a usable endpoint URL".to_owned(),
    }
}

/// Route one `key = value` into the schema: recognized keys with invalid
/// values are hard errors; unrecognized keys/sections warn.
///
/// `raw` is the value's text, unparsed. Every recognised arm parses it
/// itself — through [`parse_value`] for the ordinary keys, and through
/// `rpc_endpoints_value` for `rpc_endpoints` (D188 R5). No refusal of a
/// URL-list key repeats its value (U99, D195 R4): each names the key, the line
/// and, for an entry, its position.
fn apply(
    config: &mut Config,
    section: &[String],
    key: &str,
    full_key: &str,
    raw: &str,
    line_no: usize,
) -> Result<(), ConfigParseError> {
    let err = |detail: String| ConfigParseError {
        line: line_no,
        detail,
    };
    // The subset parse, for every key that takes an ordinary value. Its
    // refusals never repeat the value (U99, D195 R4), so the key they belong
    // to is named in front of them, with a list entry's position (U108).
    let value = |what: &str| parse_value(raw).map_err(|refusal| err(refusal.for_key(what)));
    let expect_str = |value: Value, what: &str| match value {
        Value::Str(s) => Ok(s),
        Value::Array(_) => Err(err(format!("`{what}` takes a string, not an array"))),
        Value::Bool(_) => Err(err(format!("`{what}` takes a string, not a boolean"))),
    };
    let expect_url_array = |value: Value, what: &str| -> Result<Vec<String>, ConfigParseError> {
        match value {
            Value::Array(items) => {
                for (index, item) in items.iter().enumerate() {
                    if !http_url_shape(item) {
                        // U99 (D195 R4): the entry's POSITION, never the entry.
                        // A URL refused for its shape can still carry a
                        // credential (`user:pw@host/…`, `ftp://user:pw@…`),
                        // and this check runs before the substrate's parser
                        // below could say which part is which.
                        return Err(err(format!(
                            "`{what}` entry {index} is not an http:// or https:// URL; \
                             {URL_VALUE_NOT_REPEATED}"
                        )));
                    }
                }
                Ok(items)
            }
            Value::Str(_) => Err(err(format!("`{what}` takes an array of strings"))),
            Value::Bool(_) => Err(err(format!(
                "`{what}` takes an array of strings, not a boolean"
            ))),
        }
    };
    // A49/A50: the same array shape, plus antseal-anchor's transport rule.
    // The check is the substrate's own `Endpoint::parse`, not a second URL
    // opinion here — one implementation of "which URLs this build will
    // contact", used at config load and again inside `HttpClient::send`.
    //
    // The **policy is a parameter** because the two families genuinely differ
    // and neither answer may leak into the other: `[verify]`'s replies are
    // unsigned (A49 ⇒ [`TlsPolicy::RequiredExceptLoopback`], applied by the
    // two pairs' own validators, `bitcoin_endpoint_pair` and
    // `rpc_endpoint_pair`), while a
    // `[anchors] tsa_urls` entry carries an RFC 3161 token that is signed and
    // nonce-bound, and `timestamp.digicert.com` **refuses connections on 443**
    // (measured, D90 §6.6) — so requiring TLS there would make one of the
    // spec's two default TSAs unconfigurable (A50).
    let expect_endpoint_array = |value: Value,
                                 what: &str,
                                 tls: antseal_anchor::TlsPolicy|
     -> Result<Vec<String>, ConfigParseError> {
        let items = expect_url_array(value, what)?;
        for (index, item) in items.iter().enumerate() {
            // U99 (D195 R4): the substrate's refusal, said without the URL it
            // carries — `EndpointError`'s own `Display` leads with the URL,
            // userinfo included, and one URL that does not parse at all
            // (`https://user:pw word@host/`) cannot have its credential
            // located structurally, so no redaction of that text could hold.
            antseal_anchor::Endpoint::parse(item, tls).map_err(|refusal| {
                err(format!(
                    "`{what}` entry {index} {}; {URL_VALUE_NOT_REPEATED}",
                    endpoint_refusal_without_url(&refusal)
                ))
            })?;
        }
        Ok(items)
    };

    let section_names: Vec<&str> = section.iter().map(String::as_str).collect();
    match (section_names.as_slice(), key) {
        ([], "default_network") => {
            let name = expect_str(value("default_network")?, "default_network")?;
            let id: NetworkId = name.parse().map_err(|_| {
                err(format!(
                    "`default_network` must be one of arbitrum-one, arbitrum-sepolia, \
                     devnet (got `{name}`)"
                ))
            })?;
            config.default_network = Some(id);
        }
        // D173 §2 R4: `arbitrum-one`'s storage bootstrap peers, which REPLACE
        // the vendored list wholesale and are never merged with it (the
        // resolver in `crate::devnet_env` consumes this slot). Accepted under
        // `[networks.arbitrum-one]` ONLY: the other two networks' peers come
        // from the devnet export `ANTSEAL_DEVNET_ENV` names and belong to one
        // run of a devnet, so a config key for them would be a stale layer
        // waiting to be dialed. Validated here, at load, through the one
        // peer-set classifier (D173 §2 R8) — so a bad list is exit 17 before
        // dispatch and therefore before any passphrase — and, unlike
        // `tsa_urls`, an EMPTY list is refused rather than read as "the
        // defaults": a present layer is non-empty where it is parsed, so no
        // layer is ever silently skipped (D173 §2 R6).
        (["networks", network_name], "bootstrap") => {
            let id: NetworkId = network_name
                .parse()
                .map_err(|_| err(unknown_network("networks", network_name)))?;
            if id != NetworkId::ArbitrumOne {
                return Err(err(format!(
                    "`bootstrap` is accepted under [networks.arbitrum-one] only; \
                     [networks.{id}] takes no peer override, because that network's peers \
                     come from the devnet export ANTSEAL_DEVNET_ENV names and belong to one \
                     run of a devnet"
                )));
            }
            let items = match value("bootstrap")? {
                Value::Array(items) => items,
                Value::Str(_) | Value::Bool(_) => {
                    return Err(err(
                        "`bootstrap` takes an array of \"ip:port\" strings".to_owned()
                    ));
                }
            };
            config.arbitrum_one_bootstrap = Some(parse_bootstrap_override(&items).map_err(err)?);
        }
        (["networks", network_name], other) => {
            // The section family is recognized; validate its name even
            // for unknown keys, then refuse a key this build reads elsewhere
            // (U100, D196 R1) and warn on any other (forward compat).
            // `rpc_url` never arrives here: `parse` refuses it on its key.
            let _: NetworkId = network_name
                .parse()
                .map_err(|_| err(unknown_network("networks", network_name)))?;
            if let Some(refusal) = misplaced_key_refusal(other, section) {
                return Err(err(refusal));
            }
            config.warnings.push(format!(
                "config.toml line {line_no}: unknown key `{other}` under \
                 [networks.{network_name}] — ignored (newer antseal?)"
            ));
        }
        // U26: the M2 anchor stage's effective TSA list. A present, non-empty
        // override **replaces** the built-in defaults wholesale
        // (`antseal_anchor::effective_tsa_urls`); an absent or empty one falls
        // back to them. A50: validated through the substrate's parser at load,
        // so a typo'd endpoint is a config error before any plan validation,
        // vault unlock, quote or submission — not a failed anchor an hour into
        // a seal.
        (["anchors"], "tsa_urls") => {
            config.tsa_urls = Some(expect_endpoint_array(
                value("tsa_urls")?,
                "tsa_urls",
                antseal_anchor::TlsPolicy::Optional,
            )?);
        }
        // U44 (D188 R1): the OpenTimestamps calendar list — `seal`'s submit
        // targets and the upgrade allowlist's only widening, one list in two
        // roles (U52, U64). The `tsa_urls` conventions throughout: a non-empty
        // list replaces D54's four wholesale, an empty one is the defaults,
        // and a bad entry is refused here, at load, naming the key, the line
        // and the entry's position, never the entry (U99, D195 R4: a URL can
        // carry a credential, and D188 R1's echo of a calendar URL is
        // retired). The TLS policy is the SUBMIT path's own
        // (`ots/submit.rs` parses each calendar under `TlsPolicy::Optional`:
        // a calendar cannot forge an OpenTimestamps proof, D54 §4), so load and
        // use apply one rule and cannot disagree (A50). Upgrades are fetched
        // over https only (A42) — a cost `docs/config.md` states.
        (["anchors"], "ots_calendars") => {
            config.ots_calendars = Some(expect_endpoint_array(
                value("ots_calendars")?,
                "ots_calendars",
                antseal_anchor::TlsPolicy::Optional,
            )?);
        }
        // U60 (D189 R2): the opportunistic upgrade pass's off switch. Only the
        // bare booleans load; every other spelling — `"false"`, `off`,
        // `False`, `[]` — is refused with this key's own sentence rather than
        // the subset's generic one, so a user who meant "off" is told the one
        // spelling that means it. Honoured by `upgrade_hook::run_after_output`
        // alone: `status <work-id> --upgrade` is the user asking.
        (["anchors"], "opportunistic_upgrades") => {
            let Ok(Value::Bool(on)) = parse_value(raw) else {
                return Err(err(
                    "`opportunistic_upgrades` takes true or false".to_owned()
                ));
            };
            config.opportunistic_upgrades = Some(on);
        }
        // A49 (decision D90 §6.6): the `[verify]` endpoints are the two
        // must-agree pairs, and their replies are **unsigned** — an esplora
        // block header and an `eth_getTransactionReceipt` result carry no
        // signature of their own, so they are trusted only because two
        // independent endpoints agree. Over plain HTTP one on-path attacker
        // forges both halves and the must-agree primitive reports agreement
        // on a lie, which is why transport security is not optional here.
        // The RFC 3161 slot above (`tsa_urls`) is deliberately NOT subject to
        // this: TSA tokens are signed and nonce-bound, and
        // `timestamp.digicert.com` has no port 443 at all.
        //
        // U101 (D196 R3): the whole pair is checked HERE, at load, by its one
        // validator — the function every use site calls too — so a list of
        // one, three or none, or two URLs at one origin, is exit 17 on every
        // command instead of a usage error from `verify --online`, a usage
        // error from `status --upgrade` only when something is pending, and a
        // silently skipped opportunistic pass. Every refusal names the entry's
        // position or the count, never a URL (U99, D195 R4).
        (["verify"], "bitcoin_endpoints") => {
            let items = expect_url_array(value("bitcoin_endpoints")?, "bitcoin_endpoints")?;
            bitcoin_endpoint_pair(&items).map_err(err)?;
            config.verify_bitcoin_endpoints = Some(items);
        }
        // U44 (D188 R4, R5): A17's per-network Arbitrum receipt pair. The
        // table is judged first — an unknown network keeps the
        // `[networks.<id>]` answer, devnet is refused with its reason — and
        // then the value, value-free: exactly two endpoints at two origins,
        // checked here at load by the same function `verify --online` builds
        // its pair with, and every refusal names the key, the table, the line
        // and the entry index, never a URL.
        (["verify", network_name], "rpc_endpoints") => {
            let id = verify_table_network(network_name).map_err(err)?;
            let items = rpc_endpoints_value(raw, id).map_err(err)?;
            rpc_endpoint_pair(&items, id).map_err(err)?;
            let Some(slot) = config.verify_rpc_slot(id) else {
                return Err(err(devnet_verify_refusal()));
            };
            *slot = Some(items);
        }
        (["verify", network_name], other) => {
            // The table family is recognized: its network is judged even for
            // a key this build does not know, then a key read elsewhere or
            // retired is refused (U100, D196 R1; D207) and any other warned on.
            verify_table_network(network_name).map_err(err)?;
            if let Some(refusal) = misplaced_key_refusal(other, section) {
                return Err(err(refusal));
            }
            config.warnings.push(format!(
                "config.toml line {line_no}: unknown key `{other}` under \
                 [verify.{network_name}] — ignored (newer antseal?)"
            ));
        }
        // D189 R3 (G3): an unknown key's value is NOT parsed. It is warned on
        // by its key alone — after any table name above was judged — so a
        // value in grammar this build lacks (an integer, a date, a construct a
        // newer antseal added) cannot turn a newer config into a hard error
        // here. Only a recognised key's value must be in the subset. A KNOWN
        // key here is outside its home table (U100, D196 R1) and is refused by
        // name, still without its value being parsed.
        _ => {
            if let Some(refusal) = misplaced_key_refusal(key, section) {
                return Err(err(refusal));
            }
            config.warnings.push(format!(
                "config.toml line {line_no}: unknown key `{full_key}` — ignored \
                 (newer antseal?)"
            ));
        }
    }
    Ok(())
}
