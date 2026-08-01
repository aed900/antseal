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
//! # Per-network payment-RPC override SLOT. Chain ids, contract
//! # addresses, and default RPC endpoints are antseal-net's pinned
//! # constants and are deliberately NOT configurable here — duplicating
//! # contract addresses in a hand-edited file is exactly the drift the
//! # S5 byte-equality test exists to prevent. Consumed by the backend
//! # adapter at integration (S6); validated now.
//! [networks.arbitrum-one]
//! rpc_url = "https://my-own-node.example/rpc"
//!
//! # RFC 3161 TSA list override SLOT (consumer: the M2 anchor stage,
//! # U26; empty/absent = the built-in defaults).
//! [anchors]
//! tsa_urls = ["https://freetsa.org/tsr", "http://timestamp.digicert.com"]
//!
//! # Pinned online-endpoint override SLOTS for `verify --online`
//! # (consumer: U30 at M3; two independent must-agree sources per
//! # evidence class).
//! [verify]
//! bitcoin_endpoints = ["https://a.example", "https://b.example"]
//! arbitrum_endpoints = ["https://c.example", "https://d.example"]
//! ```
//!
//! Unknown top-level keys and unknown sections are **warnings**
//! (forward compatibility: a newer antseal's config must not crash an
//! older one), rendered once on stderr and never fatal. Invalid values
//! for *recognized* keys — an unknown network name, a non-string, a
//! non-http(s) URL — are hard errors: a recognized key the loader cannot
//! honor must be loud (never a silently-dropped override).
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
//! - duplicate keys/sections are errors.
//!
//! Everything a v1 key needs is expressible; everything else — escapes,
//! multi-line strings, integers, dates, inline tables — is rejected with
//! a message naming the construct, so a hand-written full-TOML file
//! degrades into a precise complaint, never a misparse. `docs/config.md`
//! carries the user-facing statement of the same grammar.

use std::collections::BTreeMap;
use std::io::ErrorKind;

use antseal_net::NetworkId;

use crate::cli::Network;
use crate::error::CliError;
use crate::vault::layout::{BesideFile, VaultLayout};
use crate::vault::session::read_bounded;

/// Byte cap on the config file (D10 discipline; also the export-embed
/// cap — `vault/export.rs` references this same constant).
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// The parsed configuration (defaults = every field empty).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    /// `default_network` — the middle layer of the precedence rule.
    pub default_network: Option<NetworkId>,
    /// `[networks.<id>] rpc_url` override slots (consumer: S6). A
    /// short pair list — three possible networks — with
    /// [`Config::rpc_url_override`] as the reader (`NetworkId`
    /// deliberately gains no `Ord` for a map's sake).
    pub rpc_url_overrides: Vec<(NetworkId, String)>,
    /// `[anchors] tsa_urls` (consumer: U26 at M2).
    pub tsa_urls: Option<Vec<String>>,
    /// `[verify] bitcoin_endpoints` (consumer: U30 at M3).
    pub verify_bitcoin_endpoints: Option<Vec<String>>,
    /// `[verify] arbitrum_endpoints` (consumer: U30 at M3).
    pub verify_arbitrum_endpoints: Option<Vec<String>>,
    /// Unknown-key/section warnings (forward compat) — rendered once on
    /// stderr by the entry point, never fatal, never on stdout.
    pub warnings: Vec<String>,
}

impl Config {
    /// The configured RPC override for one network, if any.
    #[must_use]
    pub fn rpc_url_override(&self, id: NetworkId) -> Option<&str> {
        self.rpc_url_overrides
            .iter()
            .find(|(network, _)| *network == id)
            .map(|(_, url)| url.as_str())
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
    let bytes = match read_bounded(&path, MAX_CONFIG_BYTES + 1) {
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
        let value = parse_value(value_raw.trim()).map_err(err)?;

        apply(&mut config, &section, key, &full_key, value, line_no)?;
    }
    Ok(config)
}

/// A parsed subset value.
enum Value {
    Str(String),
    Array(Vec<String>),
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

fn parse_value(raw: &str) -> Result<Value, String> {
    if raw.starts_with('[') {
        let inner = raw
            .strip_prefix('[')
            .and_then(|r| r.strip_suffix(']'))
            .ok_or_else(|| {
                "array value must open and close on one line in this config".to_owned()
            })?;
        let mut items = Vec::new();
        let trimmed = inner.trim();
        if !trimmed.is_empty() {
            for part in split_array_items(trimmed)? {
                match parse_value(part.trim())? {
                    Value::Str(s) => items.push(s),
                    Value::Array(_) => {
                        return Err("nested arrays are outside the config subset".to_owned());
                    }
                }
            }
        }
        return Ok(Value::Array(items));
    }
    parse_string(raw).map(Value::Str)
}

/// Split a single-line array body on top-level commas (commas inside
/// quotes survive).
fn split_array_items(inner: &str) -> Result<Vec<&str>, String> {
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
        return Err("unterminated string inside array".to_owned());
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
    Err(format!(
        "value `{raw}` is not a quoted string or a [\"…\"] array \
         (integers, booleans, dates, and inline tables are outside the \
         antseal config subset)"
    ))
}

fn http_url_shape(value: &str) -> bool {
    (value.starts_with("https://") && value.len() > "https://".len())
        || (value.starts_with("http://") && value.len() > "http://".len())
}

/// Route one parsed `key = value` into the schema: recognized keys with
/// invalid values are hard errors; unrecognized keys/sections warn.
fn apply(
    config: &mut Config,
    section: &[String],
    key: &str,
    full_key: &str,
    value: Value,
    line_no: usize,
) -> Result<(), ConfigParseError> {
    let err = |detail: String| ConfigParseError {
        line: line_no,
        detail,
    };
    let expect_str = |value: Value, what: &str| match value {
        Value::Str(s) => Ok(s),
        Value::Array(_) => Err(err(format!("`{what}` takes a string, not an array"))),
    };
    let expect_url_array = |value: Value, what: &str| -> Result<Vec<String>, ConfigParseError> {
        match value {
            Value::Array(items) => {
                for item in &items {
                    if !http_url_shape(item) {
                        return Err(err(format!(
                            "`{what}` entries must be http:// or https:// URLs"
                        )));
                    }
                }
                Ok(items)
            }
            Value::Str(_) => Err(err(format!("`{what}` takes an array of strings"))),
        }
    };

    let section_names: Vec<&str> = section.iter().map(String::as_str).collect();
    match (section_names.as_slice(), key) {
        ([], "default_network") => {
            let name = expect_str(value, "default_network")?;
            let id: NetworkId = name.parse().map_err(|_| {
                err(format!(
                    "`default_network` must be one of arbitrum-one, arbitrum-sepolia, \
                     devnet (got `{name}`)"
                ))
            })?;
            config.default_network = Some(id);
        }
        (["networks", network_name], "rpc_url") => {
            let id: NetworkId = network_name.parse().map_err(|_| {
                err(format!(
                    "`[networks.{network_name}]` is not a known network (valid: \
                     arbitrum-one, arbitrum-sepolia, devnet)"
                ))
            })?;
            let url = expect_str(value, "rpc_url")?;
            if !http_url_shape(&url) {
                return Err(err(
                    "`rpc_url` must be an http:// or https:// URL".to_owned()
                ));
            }
            config.rpc_url_overrides.push((id, url));
        }
        (["networks", network_name], other) => {
            // The section family is recognized; validate its name even
            // for unknown keys, then warn on the key (forward compat).
            let _: NetworkId = network_name.parse().map_err(|_| {
                err(format!(
                    "`[networks.{network_name}]` is not a known network (valid: \
                     arbitrum-one, arbitrum-sepolia, devnet)"
                ))
            })?;
            config.warnings.push(format!(
                "config.toml line {line_no}: unknown key `{other}` under \
                 [networks.{network_name}] — ignored (newer antseal?)"
            ));
        }
        (["anchors"], "tsa_urls") => {
            config.tsa_urls = Some(expect_url_array(value, "tsa_urls")?);
        }
        (["verify"], "bitcoin_endpoints") => {
            config.verify_bitcoin_endpoints = Some(expect_url_array(value, "bitcoin_endpoints")?);
        }
        (["verify"], "arbitrum_endpoints") => {
            config.verify_arbitrum_endpoints = Some(expect_url_array(value, "arbitrum_endpoints")?);
        }
        _ => {
            config.warnings.push(format!(
                "config.toml line {line_no}: unknown key `{full_key}` — ignored \
                 (newer antseal?)"
            ));
        }
    }
    Ok(())
}
