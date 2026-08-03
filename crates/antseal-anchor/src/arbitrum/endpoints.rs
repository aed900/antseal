//! A17's per-network RPC pairs and the constants around them (decision
//! [D55](../../../../docs/decisions/D55-arbitrum-rpc-pairs.md) §4).
//!
//! Every endpoint here was chosen by probing **the method A17 actually
//! issues** against a real argument, never a cheap liveness call. D90 §6.9(b)
//! states the rule and D55 supplies the measurement that produced it:
//! `arbitrum-one-rpc.publicnode.com` answers `eth_blockNumber` in 0.75 s and
//! then rejects `eth_getTransactionReceipt` with *"Archive requests require a
//! personal token"* — so a liveness probe on a cheap method converts an
//! authorization failure into an endorsement.

use antseal_net::network::NetworkId;

/// Advisory receipt-confirmation endpoints for Arbitrum One, in the order
/// they are queried.
///
/// Slot 0 is the chain operator's own endpoint — the same URL as the
/// *payment* RPC constant (`antseal_net::network::ARBITRUM_ONE_RPC_URL`) but
/// a deliberately separate constant: different question, different process,
/// separately overridable (D33's boundary; D55 §1). Slot 1 is the independent
/// corroborator.
pub const ARBITRUM_ONE_VERIFY_RPCS: [&str; 2] =
    ["https://arb1.arbitrum.io/rpc", "https://arbitrum.drpc.org"];

/// Advisory receipt-confirmation endpoints for Arbitrum Sepolia
/// (chain 421614 — **not** Ethereum Sepolia).
pub const ARBITRUM_SEPOLIA_VERIFY_RPCS: [&str; 2] = [
    "https://sepolia-rollup.arbitrum.io/rpc",
    "https://arbitrum-sepolia.drpc.org",
];

/// Documented reserves, never contacted by default.
///
/// `1rpc.io/arb` serves receipts correctly but returns
/// `Access-Control-Allow-Origin: *` on the CORS **preflight** and none on the
/// **POST**, so a browser passes preflight and then discards the response
/// (D55 §2 round 3). It is CLI-only and must never be promoted into a default
/// pair while M3's page shares these constants.
pub const ARBITRUM_ONE_RESERVE_RPCS_CLI_ONLY: [&str; 1] = ["https://1rpc.io/arb"];

/// The pair for a network, or `None` for devnet.
///
/// `None` rather than an empty slice, so "there is no overlay here" cannot be
/// read as "the overlay found nothing": a devnet chain is a fresh Anvil
/// instance per run, there is no second endpoint to agree with, and devnet
/// seals are not evidence (D55 §5).
#[must_use]
pub const fn verify_rpcs(network: NetworkId) -> Option<&'static [&'static str; 2]> {
    match network {
        NetworkId::ArbitrumOne => Some(&ARBITRUM_ONE_VERIFY_RPCS),
        NetworkId::ArbitrumSepolia => Some(&ARBITRUM_SEPOLIA_VERIFY_RPCS),
        NetworkId::Devnet => None,
    }
}

/// The chain id the guard requires, or `None` for devnet (run-scoped — it
/// comes from `DevnetEnv`, and the overlay is disabled there anyway).
///
/// The values are **consumed by name** from `antseal_net::network`, never
/// re-typed: the payment path already carries this guard
/// (`ant_backend.rs:217`) and two independently written chain ids that agree
/// today is how they stop agreeing later.
#[must_use]
pub const fn expected_chain_id(network: NetworkId) -> Option<u64> {
    match network {
        NetworkId::ArbitrumOne => Some(antseal_net::network::ARBITRUM_ONE_CHAIN_ID),
        NetworkId::ArbitrumSepolia => Some(antseal_net::network::ARBITRUM_SEPOLIA_CHAIN_ID),
        NetworkId::Devnet => None,
    }
}

/// The JSON-RPC method A17 issues for the receipt.
pub const METHOD_GET_TRANSACTION_RECEIPT: &str = "eth_getTransactionReceipt";
/// The JSON-RPC method the guard issues.
pub const METHOD_CHAIN_ID: &str = "eth_chainId";
/// `Content-Type` for a JSON-RPC POST.
pub const RPC_CONTENT_TYPE: &str = "application/json";

// The per-response body cap and the per-request timeout are **not** redefined
// here. D55 §4 proposed `MAX_ARBITRUM_RPC_RESPONSE_BYTES = 262_144` and
// `ARBITRUM_VERIFY_REQUEST_TIMEOUT_SECS = 10`; D55 §7b then raised the cap to
// 512 KiB against D90's substrate, and the timeout is D90's
// `HTTP_TIMEOUT_GLOBAL` under `HttpPolicy::verify()`. Both live on the
// substrate (`crate::http::RPC_RESPONSE_CAP_BYTES`,
// `crate::http::HTTP_TIMEOUT_GLOBAL`) and are consumed from there, so the
// superseded §4 values cannot be resurrected here by a reader who stops at §4.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Endpoint, TlsPolicy};
    use antseal_net::network::{ARBITRUM_ONE_CHAIN_ID, ARBITRUM_SEPOLIA_CHAIN_ID};

    /// D55 §7's `default_pairs_are_exactly_two_per_live_network_and_none_on_devnet`.
    ///
    /// Pins the literals **and their order** (slot 0 is the chain operator),
    /// so an edit to the constants without an edit to D55 goes red.
    #[test]
    fn default_pairs_are_exactly_two_per_live_network_and_none_on_devnet() {
        assert_eq!(
            verify_rpcs(NetworkId::ArbitrumOne),
            Some(&["https://arb1.arbitrum.io/rpc", "https://arbitrum.drpc.org"])
        );
        assert_eq!(
            verify_rpcs(NetworkId::ArbitrumSepolia),
            Some(&[
                "https://sepolia-rollup.arbitrum.io/rpc",
                "https://arbitrum-sepolia.drpc.org",
            ])
        );
        assert_eq!(verify_rpcs(NetworkId::Devnet), None);
        assert_eq!(expected_chain_id(NetworkId::Devnet), None);
        assert_eq!(
            expected_chain_id(NetworkId::ArbitrumOne),
            Some(ARBITRUM_ONE_CHAIN_ID)
        );
        assert_eq!(
            expected_chain_id(NetworkId::ArbitrumSepolia),
            Some(ARBITRUM_SEPOLIA_CHAIN_ID)
        );
        // The values themselves, so a rename in `antseal-net` that swapped
        // them would not pass by construction.
        assert_eq!(ARBITRUM_ONE_CHAIN_ID, 42_161);
        assert_eq!(ARBITRUM_SEPOLIA_CHAIN_ID, 421_614);
    }

    /// Every default is https and every pair is two distinct origins.
    ///
    /// The first half is A49: an RPC reply is unsigned, so transport is its
    /// only integrity control. The second is A16's pair rule — a pair that is
    /// one origin agrees with itself.
    #[test]
    fn every_default_is_https_and_the_pairs_are_distinct_origins() {
        for network in [NetworkId::ArbitrumOne, NetworkId::ArbitrumSepolia] {
            let urls = verify_rpcs(network).expect("a live network has a pair");
            let parsed: Vec<Endpoint> = urls
                .iter()
                .map(|url| {
                    Endpoint::parse(url, TlsPolicy::RequiredExceptLoopback)
                        .unwrap_or_else(|e| panic!("{network}: {url}: {e}"))
                })
                .collect();
            for endpoint in &parsed {
                assert!(endpoint.is_https(), "{}", endpoint.url());
            }
            assert_ne!(
                parsed[0].origin(),
                parsed[1].origin(),
                "{network}'s pair is one origin twice"
            );
        }

        // And the CLI-only reserve is never in a default pair, on either
        // network — the CORS finding is what keeps it out.
        for network in [NetworkId::ArbitrumOne, NetworkId::ArbitrumSepolia] {
            let urls = verify_rpcs(network).expect("a live network has a pair");
            for reserve in ARBITRUM_ONE_RESERVE_RPCS_CLI_ONLY {
                assert!(!urls.contains(&reserve), "{reserve} is in {network}'s pair");
            }
        }
    }

    /// The two networks' pairs share no endpoint.
    ///
    /// A Sepolia endpoint asked about a mainnet transaction answers `null`,
    /// which this design classifies as `Lagging` — a misconfiguration
    /// rendered as a benign sync artifact (D55 §6). The chain-id guard is the
    /// runtime defence; this is the compile-time one.
    #[test]
    fn the_two_networks_share_no_endpoint() {
        let one = verify_rpcs(NetworkId::ArbitrumOne).expect("pair");
        let sepolia = verify_rpcs(NetworkId::ArbitrumSepolia).expect("pair");
        for url in one {
            assert!(!sepolia.contains(url), "{url} serves both networks");
        }
    }
}
