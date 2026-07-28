//! **Why every commitment is salted** — the confirmation attack, executed
//! (task C19; MVP-SPEC.md line 171: *"Adversarial doc-tests: demonstrate the
//! confirmation attack against an unsalted unit variant **and** an unsalted
//! file-hash variant (regression guards for why every commitment is
//! salted)"*).
//!
//! This module contains no code. It contains two attacks, and both of them
//! run: the doc-tests below are compiled and executed by `cargo test` on
//! every CI run, and they fail loudly if the salted constructions ever stop
//! defeating them. They are documentation *and* regression guards, which is
//! why they live in the rendered API docs rather than in a test file nobody
//! reads.
//!
//! # The attack
//!
//! A commitment is *binding* if the committer cannot change their mind about
//! the committed value, and *hiding* if a holder of the commitment learns
//! nothing about that value. A bare hash `H(m)` is binding but **not
//! hiding whenever `m` is guessable**: an adversary who suspects `m = m*`
//! simply computes `H(m*)` and compares. Nothing is brute-forced — the
//! adversary needs only the candidate they already had in mind.
//!
//! Work under antseal is exactly the guessable kind. Paragraphs of prose,
//! contract clauses, filenames, single bytes of a fine-tree leaf: the
//! plausible-plaintext space is small enough to enumerate by hand. So the
//! spec's Context corollary (line 13) is absolute —
//!
//! > **nothing content-derived is ever stored or shipped unsalted —
//! > including per-file hashes**
//!
//! — and line 93 restates it for the commitments specifically: *every*
//! content commitment is salted, "an unsalted hash anywhere would re-enable
//! the confirmation attack this design exists to prevent, including against
//! bundle recipients guessing unrevealed files".
//!
//! Salting turns `H(tag ‖ m)` into `H(tag ‖ salt ‖ m)` with a secret,
//! 128-bit, per-unit or per-file `salt` derived from the vault-held master
//! secret `W`. The adversary must now guess the salt as well as the message
//! — 2¹²⁸ work per candidate — which is the hiding margin the spec's
//! security-assumptions block claims (line 101, random-oracle model). The
//! commitment stays exactly as binding as before: SHA-256 collision
//! resistance is untouched by prepending a salt.
//!
//! # Two variants, because there are two ways to get this wrong
//!
//! The doc-tests below cover both:
//!
//! 1. **Unsalted unit** — the per-unit commitment. The victim is anyone
//!    holding the manifest, which carries `unit_commit` for every
//!    non-fine-tree-covered unit whether or not that unit is ever revealed.
//! 2. **Unsalted file hash** — the per-file content commitment. The victim
//!    is a *bundle recipient*: `canon_commit`/`raw_commit` sit in the
//!    manifest embedded in **every** bundle, so a single-unit partial reveal
//!    would hand its recipient an offline whole-document confirmation oracle
//!    (spec line 95). This is the variant the two-independent-salts design
//!    exists for, and it is why `file_salt` is reachable only through
//!    [`FullFileRevealDisclosure`](super::disclosure::FullFileRevealDisclosure)
//!    — on a full reveal the content is shown anyway, so disclosing its salt
//!    costs nothing.
//!
//! # 1. The unsalted-unit variant
//!
//! An attacker holds the manifest and suspects what one sealed paragraph
//! says. Against the unsalted construction they confirm it offline; against
//! the real [`unit_commit`](super::commit::unit_commit) they cannot.
//!
//! ```
//! use antseal_core::crypto::commit::{unit_commit, verify_unit_commit};
//! use antseal_core::crypto::domain::{TAG_UNIT_COMMIT, tagged_sha256};
//! use antseal_core::crypto::hkdf::{UnitId, derive_unit_salt};
//! use antseal_core::crypto::material::{MasterSecretRef, Salt16};
//!
//! // Fixed, public, NON-SECRET fixture W (project rule 6). The real one
//! // never leaves the vault — which is the whole point of what follows.
//! let w_bytes = [0x11u8; 32];
//! let w = MasterSecretRef::from_bytes(&w_bytes);
//! let unit_id = UnitId(7);
//!
//! // The sealed paragraph. Low entropy: an attacker who knows roughly what
//! // this document is about can write down every sentence it might contain.
//! let sealed: &[u8] = b"We will acquire Northwind on 2026-08-14.";
//! let candidates: [&[u8]; 4] = [
//!     b"We will acquire Eastgate on 2026-08-14.",
//!     b"We will acquire Northwind on 2026-08-14.", // the attacker's true guess
//!     b"We will acquire Northwind on 2026-09-01.",
//!     b"We will not acquire anyone this year.",
//! ];
//!
//! // ---- (a) the deliberately UNSALTED toy: the attack SUCCEEDS ----
//! //
//! // Same domain tag, same hash, no salt: SHA-256(0x02 || unit_bytes).
//! let unsalted_commitment = tagged_sha256(TAG_UNIT_COMMIT, &[sealed]);
//!
//! let confirmed: Vec<&[u8]> = candidates
//!     .iter()
//!     .copied()
//!     .filter(|guess| tagged_sha256(TAG_UNIT_COMMIT, &[guess]) == unsalted_commitment)
//!     .collect();
//!
//! // The attacker has learned the exact contents of a unit that was never
//! // revealed to them, from the manifest alone, at the cost of four hashes.
//! assert_eq!(confirmed, vec![sealed]);
//!
//! // ---- (b) the PRODUCTION construction: the attack FAILS ----
//! //
//! // unit_commit = SHA-256(0x02 || unit_salt || unit_bytes), with
//! // unit_salt = HKDF(W, "unit-salt", unit_id) — 16 secret bytes the
//! // attacker does not have (MVP-SPEC.md line 94).
//! let unit_salt = derive_unit_salt(w, unit_id);
//! let real_commitment = unit_commit(&unit_salt, sealed);
//!
//! // The attacker still knows the right answer. It no longer helps: with no
//! // salt to put in the preimage, every guess — including the correct one —
//! // fails against every salt they can try.
//! for attempted_salt in [Salt16::from_bytes([0x00; 16]), Salt16::from_bytes([0xff; 16])] {
//!     for guess in candidates {
//!         assert!(verify_unit_commit(&attempted_salt, guess, &real_commitment).is_err());
//!     }
//! }
//! // Not even the unsalted preimage happens to match:
//! assert_ne!(tagged_sha256(TAG_UNIT_COMMIT, &[sealed]), real_commitment);
//!
//! // The attacker's remaining option is to search the salt space: 2^128
//! // candidates, per guessed message. That is the hiding margin.
//! assert_eq!(Salt16::LEN * 8, 128);
//!
//! // Hiding was restored WITHOUT weakening binding: given the salt — i.e.
//! // on a legitimate reveal of this unit — the commitment opens exactly as
//! // before, and only to the real content.
//! assert!(verify_unit_commit(&unit_salt, sealed, &real_commitment).is_ok());
//! assert!(verify_unit_commit(&unit_salt, candidates[0], &real_commitment).is_err());
//!
//! // And the salt is per-unit, so revealing this unit does not open the
//! // next one: two units with byte-identical content stay unlinkable.
//! let other_salt = derive_unit_salt(w, UnitId(8));
//! assert_ne!(unit_commit(&other_salt, sealed), real_commitment);
//! assert!(verify_unit_commit(&unit_salt, sealed, &unit_commit(&other_salt, sealed)).is_err());
//! ```
//!
//! # 2. The unsalted-file-hash variant
//!
//! This is the sharper one, because the attacker is not an outsider: they
//! are someone the sealer *chose* to show one paragraph to. They hold a
//! legitimate bundle. Inside it is the manifest, and in the manifest is the
//! file's content commitment — for a file they were shown almost none of.
//!
//! Against an unsalted `canon_commit` that commitment is a whole-document
//! confirmation oracle. Against the real construction it is inert, because
//! `file_salt` is structurally unobtainable on a partial reveal: the
//! disclosure type for a touched-but-not-fully-revealed file has no slot for
//! it (C7), and the only public byte path runs through the full-reveal
//! witness — where the document is shown anyway, so the salt discloses
//! nothing new.
//!
//! ```
//! use antseal_core::crypto::commit::{canon_commit, verify_canon_commit};
//! use antseal_core::crypto::disclosure::{
//!     FullFileRevealContext, FullFileRevealDisclosure, PartialRevealDisclosure,
//! };
//! use antseal_core::crypto::domain::{TAG_CANON_COMMIT, tagged_sha256};
//! use antseal_core::crypto::hkdf::{FileId, UnitId, derive_file_salt};
//! use antseal_core::crypto::material::{FileSalt, MasterSecretRef, Salt16};
//!
//! // Fixed, public, NON-SECRET fixture W (project rule 6).
//! let w_bytes = [0x22u8; 32];
//! let w = MasterSecretRef::from_bytes(&w_bytes);
//! let file_id = FileId(3);
//!
//! // A three-unit contract. The sealer reveals unit 0 only — the recipient
//! // is meant to learn the first clause and nothing else.
//! let all_units = [UnitId(0), UnitId(1), UnitId(2)];
//! let revealed = [UnitId(0)];
//! let document: &[u8] =
//!     b"1. Term: 24 months.\n2. Fee: 4% of gross.\n3. Exclusivity: none.\n";
//!
//! // What the recipient can guess: they know the template and the parties,
//! // so the unrevealed clauses come from a short list.
//! let candidates: [&[u8]; 3] = [
//!     b"1. Term: 24 months.\n2. Fee: 2% of gross.\n3. Exclusivity: none.\n",
//!     b"1. Term: 24 months.\n2. Fee: 4% of gross.\n3. Exclusivity: none.\n",
//!     b"1. Term: 24 months.\n2. Fee: 4% of gross.\n3. Exclusivity: full.\n",
//! ];
//!
//! // ---- (a) the deliberately UNSALTED toy: the attack SUCCEEDS ----
//! //
//! // SHA-256(0x04 || canonical_bytes), no file_salt.
//! let unsalted_commitment = tagged_sha256(TAG_CANON_COMMIT, &[document]);
//!
//! let confirmed: Vec<&[u8]> = candidates
//!     .iter()
//!     .copied()
//!     .filter(|guess| tagged_sha256(TAG_CANON_COMMIT, &[guess]) == unsalted_commitment)
//!     .collect();
//!
//! // The recipient of a ONE-UNIT reveal has just confirmed the entire
//! // document, including the fee they were never shown. The reveal was
//! // selective; the disclosure was not.
//! assert_eq!(confirmed, vec![document]);
//!
//! // ---- (b) the PRODUCTION construction: the attack FAILS ----
//! //
//! // canon_commit = SHA-256(0x04 || file_salt || canonical_bytes), with
//! // file_salt = HKDF(W, "file-salt", file_id) (MVP-SPEC.md line 95).
//! let file_salt = derive_file_salt(w, file_id);
//! let real_commitment = canon_commit(&file_salt, document);
//!
//! // The partial-reveal disclosure set is what the recipient actually
//! // holds. It carries `path_salt` — so they can verify the file's path —
//! // and the revealed units' salts. It has no `file_salt`, and no accessor
//! // that could produce one.
//! let partial = PartialRevealDisclosure::new(w, file_id);
//!
//! // Their best available guess at the salt is the one salt they DO hold.
//! // The two per-file salts derive from independent HKDF labels precisely
//! // so that disclosing the path never compromises the content:
//! let path_salt_as_file_salt =
//!     FileSalt::from_disclosed(Salt16::from_bytes(*partial.path_salt().as_bytes()));
//! for guess in candidates {
//!     assert!(verify_canon_commit(&path_salt_as_file_salt, guess, &real_commitment).is_err());
//! }
//! // Arbitrary salt guesses fare no better, and neither does the correct
//! // document with the wrong salt.
//! for attempted in [Salt16::from_bytes([0x00; 16]), Salt16::from_bytes([0xff; 16])] {
//!     let attempted = FileSalt::from_disclosed(attempted);
//!     assert!(verify_canon_commit(&attempted, document, &real_commitment).is_err());
//! }
//! assert_ne!(tagged_sha256(TAG_CANON_COMMIT, &[document]), real_commitment);
//!
//! // The recipient cannot mint the full-reveal witness either: attesting
//! // full coverage from a one-unit reveal is refused, so there is no path
//! // to the salt at all.
//! assert!(FullFileRevealContext::attest(file_id, &all_units, &revealed).is_none());
//!
//! // On a genuine FULL reveal the salt is disclosed — and discloses
//! // nothing, because the document itself is right there. Verification
//! // works exactly as it always did:
//! let context = FullFileRevealContext::attest(file_id, &all_units, &all_units)
//!     .expect("a full reveal covers every non-mirror unit");
//! let full = FullFileRevealDisclosure::new(w, context);
//! let disclosed = FileSalt::from_disclosed(Salt16::from_bytes(*full.file_salt_bytes()));
//! assert!(verify_canon_commit(&disclosed, document, &real_commitment).is_ok());
//! assert!(verify_canon_commit(&disclosed, candidates[0], &real_commitment).is_err());
//! ```
//!
//! # If you are about to change a commitment
//!
//! These two tests are the standing guard on one rule: **do not remove a
//! salt from a commitment preimage, and do not introduce a new
//! content-derived value that lacks one.** That includes values which look
//! like metadata — a per-file hash is content-derived (spec line 13
//! names it explicitly), and so is a fine-tree leaf over a single byte,
//! which is why those get GGM-derived per-leaf salts rather than none
//! (line 96).
//!
//! The symmetric rule on the *disclosure* side is C7's, enforced by the
//! type system rather than by a test: a salt that is never disclosed on a
//! partial reveal cannot be misused on one.
//!
//! Cross-references: the frozen Security-assumptions block (C20) cites this
//! module as the executable form of its hiding claim; the tamper matrix
//! (Q7/Q8) covers the *binding* side, where a wrong salt or wrong bytes must
//! fail with a distinct error.
