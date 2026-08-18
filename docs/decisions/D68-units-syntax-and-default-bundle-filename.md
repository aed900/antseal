# D68 — `--units` acceptance envelope (ranges refused) + `reveal`'s default output filename

- **Status: RESOLVED — (1) `--units` takes a comma-separated list of
  work-global unit ids and nothing else; the shipped parser
  (`value_delimiter = ','`, `Vec<u64>`) is **ratified as-is** and range
  notation (`3-5`, `3..5`) is refused for MVP, but on the id space's own
  properties rather than on the spec's example — with a new obligation the
  refusal creates: a range-shaped value must be rejected by a message that
  names the supported form, not by clap's bare `invalid digit found in
  string`. (2) The default output path is
  `./antseal-reveal-<work-id>.sealproof` — invocation cwd, D29's 64-lowercase-hex
  work-id, closed `[0-9a-f]` alphabet, bounded at 89 bytes by construction; it
  embeds the `work_id` and **nothing else content-derived**, because the title
  is free-form unbounded user-controlled text and a title-derived name is a
  path-injection and audience-widening surface. An existing target is
  **refused, never overwritten, never suffixed, never timestamped, never
  prompted**, and the check runs **before the disclosure-consent gate and
  before any network fetch**, so no user is ever asked to consent to an
  irreversible disclosure that then cannot be written.**
- **Date: 2026-08-12** (wave 18 Act 1, D68 planning lane; briefed to overturn
  both halves. Half 1's lean **survives ON MEASUREMENT** with its argument
  replaced — the spec-example reasoning it rested on is defeated by spec line
  149's own `…`, and the id space supplies a stronger one. Half 2's "trivial
  pick" framing is **overturned**: the obvious friendly choice is a security
  defect, the two in-house precedents disagree and neither transfers, and the
  ruling's load-bearing clause is an ordering rule no filename-only framing
  reaches.)
- **Owning tasks: U28** (`reveal` wiring — its Do defers both halves to "open
  decision 12"), **U1** (owns the clap surface and the frozen help snapshot
  both halves change), **U29** (the consent gate the collision check must
  precede), **R16** (its `RevealOutput` doc already forward-declares "a
  D48-class overwrite policy" this record now defines), **U2** (numeric exit
  code for the new class).
- **Amends**: `tasks/U.md` U28 `Do` and `Accept` (quoted in §8.1), `tasks/U.md`
  U1 (§8.2), `tasks/U.md` open decision 12 (§7). **Supersedes**: nothing.
  **Corrects**: nothing. **Departs from a landed precedent, with reasons**:
  U12's timestamped default-filename mechanism (§3 R7, §4).

---

## 1. What was measured

### (a) The spec constrains the syntax in one place and explicitly does not in the other

`MVP-SPEC.md` line 36 (a *flow example*):

> `antseal reveal <work-id> (--all | --units 3,5) -o pitch.sealproof`

`MVP-SPEC.md` line 149, the section headed *"CLI surface (MVP — **this list is
canonical**; the flows above are examples of it)"*:

> `reveal <work-id> (--all | --units …) [-o file] [--include-receipt] [--yes]`

The canonical list spells the argument `…`, not `3,5`. So **"the spec says
comma list" is false as an argument from authority** — line 36 is expressly an
example of line 149, and line 149 declines to constrain the value syntax. The
register's stated ground for refusing ranges ("comma list per spec example")
does not survive its own citation. Any refusal has to be earned elsewhere.

### (b) `unit_id` is a dense, gapless, work-global ordinal from 0 — so a range is *arithmetically* well-posed

`MVP-SPEC.md` line 76:

> **`unit_id`** = work-global LE64 ordinal in manifest order (also the id
> `reveal --units` takes — file-scoped numbering would silently derive
> identical keys/salts across files)

Confirmed in construction, `crates/antseal-core/src/content/unit.rs:423-453`:
`next_id` starts at `0`, increments by exactly 1 per unit, and is never reset
per file. There are no gaps, no per-file restarts, no hashes, no composites.
**The brief's strongest available overturn — "ranges are ill-posed because ids
are not dense" — is not available. Ids are dense.** Any refusal of ranges must
therefore be a refusal on *semantics*, not on *arithmetic*.

### (c) …but raw mirrors sit at *invisible* positions inside that same dense space

Same function, `content/unit.rs:439-448` (comment verbatim: *"D23 step 3: the
mirror is the file's last unit, in the raw domain"*): a mirror-bearing file's
units occupy `[first … last-normal, mirror]`, and the next file resumes at
`mirror + 1`. Mirrors are therefore **interleaved**, one per mirror-bearing
file, at positions determined by `needs_mirror ⟺ raw ≠ canonical` — i.e. by
whether some earlier file happened to carry a CRLF, a BOM, or NFD (spec line
92). Those are properties a user cannot see in their source files and cannot
see in a range's notation.

For a work of file A (3 normal units + mirror) then file B (2 normal units):

| id | 0 | 1 | 2 | 3 | 4 | 5 |
|---|---|---|---|---|---|---|
| | A norm | A norm | A norm | **A mirror** | B norm | B norm |

`--units 1-4` spans a mirror. Whether it does is invisible in `1-4`.

### (d) The mirror rejection is a *resolution*-layer error, not a parse-layer one

`crates/antseal-core/src/content/mirror.rs:187-192` — `mirror_selectable`
returns `Err(ContentError::RawMirrorNotUnitSelectable)` for
`RevealSelection::UnitIds` and `Ok(())` for `All`/`WholeFile`. The CLI seam
maps it with the id attached
(`crates/antseal-cli/src/pipeline/reveal.rs:284-299`, message at `:292-293`):

> `unit {unit_id} is this file's raw mirror and cannot be selected by id; raw
> mirrors are included only by revealing the whole file (select all of its
> units) or by --all`

and the preview seam re-checks it independently
(`crates/antseal-cli/src/preview.rs:626-633`, `PreviewError::RawMirrorSelected`).
**Consequence for this decision:** a range expanded to ids *before* resolution
inherits this rejection unchanged. A range does not need new mirror
semantics — which defuses the naive objection to ranges, and forces the real
one (§2.1).

### (e) D70 makes a `--units` selection able to *promote* into a full-file reveal

`tasks/R.md` R16 Notes, D70's ruling as recorded there: the mirror rides *"iff
the resolved per-file shape is full and the file has one, **including on
promotion** (a `--units` subset completing a file pulls `file_salt`, `s_root`,
and the mirror)"*. And `file_salt` is not one more field — `MVP-SPEC.md` line
95 makes its disclosure load-bearing:

> a shared salt would hand any recipient of a single-unit partial reveal an
> offline full-file confirmation oracle (recompute `canon_commit` for a guessed
> document — exactly the confirmation attack this design exists to prevent)

So completing a file is a **category change in what the bundle discloses**, not
an increment. (D28 then makes the full-reveal shape strict; the preview
annotates all three via `PreviewTotals::mirror_rides_along`,
`preview.rs:581-583`.)

### (f) The `--units` parser is already shipped, already snapshot-frozen, and already test-pinned

`crates/antseal-cli/src/cli.rs:371-374`:

```rust
/// Reveal exactly these units (work-global ordinals as printed by
/// `show`), e.g. --units 3,5
#[arg(long, value_delimiter = ',', value_name = "UNIT")]
pub units: Vec<u64>,
```

The frozen help snapshot promises the comma form in user-facing copy,
`crates/antseal-cli/tests/snapshots/cli-surface.help.txt:276-277`:

```
      --units <UNIT>
          Reveal exactly these units (work-global ordinals as printed by `show`), e.g. --units 3,5
```

and `crates/antseal-cli/tests/cli_surface.rs:194-198` asserts
`--units 3,5` parses to `vec![3, 5]`. **Half 1 is therefore not a greenfield
choice; it is a ratification-or-amendment of shipped, frozen behaviour**, and
any divergence between ruling and parser is a defect to report rather than a
preference to state.

### (g) What the shipped parser actually accepts and rejects — measured, not inferred

Run against the prebuilt `./target/debug/antseal` (no rebuild; `reveal`'s
handler is still `NotImplemented`, `crates/antseal-cli/src/run.rs:49,60`, so
exit 3 = *"parsed, dispatched"* and exit 2 = *"clap refused"*):

```
$ antseal reveal w1 --units 3-5
error: invalid value '3-5' for '--units <UNIT>': invalid digit found in string
exit=2

$ antseal reveal w1 --units 3..5
error: invalid value '3..5' for '--units <UNIT>': invalid digit found in string
exit=2

$ antseal reveal w1 --units 3,5
error: `antseal reveal` is not implemented until M3: …
exit=3                                   ← comma list parses

$ antseal reveal w1 --units 3 --units 5
error: `antseal reveal` is not implemented until M3: …
exit=3                                   ← repeated flag also parses

$ antseal reveal w1 --units ''
error: invalid value '' for '--units <UNIT>': cannot parse integer from empty string
exit=2
$ antseal reveal w1 --units 3,,5          ← same error
$ antseal reveal w1 --units 3,5,          ← same error

$ antseal reveal w1 --units
error: a value is required for '--units <UNIT>' but none was supplied
exit=2

$ antseal reveal w1 --units -1
error: unexpected argument '-1' found
exit=2                                   ← a leading '-' is read as a flag, never a value

$ antseal reveal w1 --units 99999999999999999999
error: invalid value '99999999999999999999' for '--units <UNIT>': number too large to fit in target type
exit=2

$ antseal reveal w1 --units +3
exit=3                                   ← accepted: Rust's u64 FromStr takes a leading '+'
$ antseal reveal w1 --units 0x3
error: invalid value '0x3' for '--units <UNIT>': invalid digit found in string
exit=2
```

Three findings fall out. **(i)** Range notation already fails, but with a
generic digit message that never names the supported form — and the spec's own
example being a comma list guarantees users will try `3-5`. **(ii)** A leading
`-` is consumed as a flag, so no range-adjacent syntax could ever use a bare
leading hyphen operand. **(iii)** `RevealError::EmptySelection`
(`pipeline/reveal.rs:272-275`, *"`--units` was given with no ids"*) is
**unreachable from the CLI** — every empty spelling dies in clap first. It is
correct as a library-API defensive arm (R16 is a library API); it is not an
Accept row U28 can exercise through the binary.

### (h) `reveal` has no default output path today, and its help promises none

`crates/antseal-cli/src/cli.rs:363-365`:

```rust
/// Write the proof bundle here
#[arg(short = 'o', value_name = "FILE")]
pub output: Option<PathBuf>,
```

Compare the two sibling commands, which both *name their default in the frozen
help text*: restore's `-o <DIR>` reads *"Output directory (default per D48's
output policy)"* (`cli.rs:153-155`, snapshot line 241) and `vault export`'s
positional reads *"Output file (default naming per U12)"* (snapshot line 361).
Reveal's reads only *"Write the proof bundle here"* (snapshot lines 279-280).
Since `-o` is optional in the canonical surface (line 149's `[-o file]`), a
default must exist — so **this ruling has a frozen-snapshot consequence**, which
the "trivial pick" framing did not anticipate.

`R16` already forward-declared the shape it expects
(`crates/antseal-cli/src/pipeline/reveal.rs:226-228`): *"Writing them to disk is
U28's (`-o`, D48-class overwrite policy); this module performs no file I/O."*

### (i) The house has **two** default-name precedents and they disagree

- **D48 §1** (`restore`): `./antseal-restore-<work-id>/`, deterministic and
  work-scoped, *"a re-run of the same work land[s] in the same directory"*.
  Implemented at `crates/antseal-cli/src/restore_out.rs:56-68`
  (`OUTPUT_DIR_PREFIX` + `default_output_dir`), work-id rendered by `hex32`
  (`crates/antseal-cli/src/pipeline/restore.rs:1000-1007`, 64 lowercase hex).
- **U12** (`vault export`): `antseal-vault-export-YYYYMMDD-HHMMSS.sealvault`,
  timestamped — its execution note gives the reason verbatim: *"timestamped so
  repeated exports never silently replace a backup"*. Implemented at
  `crates/antseal-cli/src/commands.rs:537-542`, pinned by
  `default_export_name_is_timestamped_and_extension_advisory`
  (`commands.rs:584-587`), extension constant at
  `crates/antseal-cli/src/vault/export.rs:185`.

Both satisfy "never silently replace"; they satisfy it by opposite mechanisms.
Picking one over the other is the substance of half 2, and it cannot be done by
citing precedent — only by measuring which command `reveal` resembles.

### (j) D48's byte-aware convergence is **structurally unavailable** to `reveal`

D48 §3's safety rests on one property: an existing byte-identical target is
*proof of prior success*, because restore's output is a function of immutable
sealed content. Reveal has neither half of that.

1. **Different selections, same work.** `--units 3,5` for one counterparty and
   `--units 7,9` for another are two different artifacts that a work-scoped
   name maps to one path. This is the ordinary case, not an edge.
2. **Same selection, different bytes — by design.** `MVP-SPEC.md` line 35:
   *"**every CLI invocation opportunistically attempts pending OTS upgrades**"*,
   and `tasks/R.md` R16's Deps: *"the opportunistic upgrade hook (A15) is
   invoked by U's command dispatch **before this API runs**"*. An upgrade that
   lands between two reveals changes the bundle's anchor artifacts —
   `block_height`, `block_header`, `fetch_date` are carried per anchor
   (`crates/antseal-core/src/bundle/schema.rs:444-495`, `:620-682`). So the
   second bundle differs from the first **and is strictly better evidence**.

**Restore's output is a function of immutable sealed content; reveal's output
is a function of the anchor set, which this product is designed to improve over
time.** D48 §3's "identical ⇒ already-done" row has no analogue here, and any
ruling that assumed one would be wrong on the product's own upgrade story.

### (k) The title is free-form, unbounded, user-controlled text

`crates/antseal-core/src/manifest/error.rs:255`:

> `title`/`app_version` are free-form `tstr`s with no principled maximum,
> transitively bounded by `MAX_MANIFEST_BYTES`

There is no length cap, no character class, no control-character or separator
rejection anywhere on it (searched `crates/antseal-core/src/manifest/` and the
codec caps). It is embedded in the manifest that every bundle carries and the
sealer is warned it is recipient-visible (spec line 34). **A title-derived
filename would therefore take an unbounded, unvalidated, attacker-influenced
string and use it to author a filesystem path.**

### (l) The extension is spelled one way everywhere — and has no constant

Repo-wide scan of extension-shaped tokens across `crates docs verifier-web
scripts MVP-SPEC.md tasks TODO.md` (`*.rs *.md *.html *.js *.py`):

```
    210 .sealproof
     40 .seal          ← all method calls `pipeline.seal(…)`, verified at
                          crates/antseal-cli/tests/seal_pipeline.rs:82-86
```

and over bare tokens: `249 sealproof` (paths/strings) + `221 SealProof` (the
Rust type). **No `.sealprf`, `.seal-proof`, `.proof` or any other spelling
exists.** Spec line 112 heads the section *"### Reveal bundle (`.sealproof`,
versioned deterministic CBOR)"*; the verifier page says the same
(`verifier-web/index.html:12`). But unlike `.sealvault`, **no constant holds
it** — `grep -rn 'BUNDLE_FILE_EXTENSION\|SEALPROOF_EXT\|"sealproof"'` over
`crates/ verifier-web/ scripts/` returns only test literals (`"b.sealproof"`,
`"bundle.sealproof"`) and one `Debug` field name
(`pipeline/reveal.rs:239`). The house pattern (`EXPORT_FILE_EXTENSION`,
`export.rs:185`) is unmatched here.

---

## 2. The arms, refused on measurement

### 2.1 "Ranges in for MVP" (the briefed overturn) — refused

Ranges are cheap: expand `a-b` to ids at parse time and every downstream rule
(unknown id, mirror rejection §1 d, dedup, D70 promotion) applies unchanged.
That is the arm's real strength and it survives §1 (d) intact. It is refused on
three measurements the "expand-then-resolve" framing does not reach.

- **The id space is not a safe domain for a *predicate*.** A comma list is an
  *enumeration of ids the user has read off `show`* — the surface spec line 149
  calls *"the preview for `reveal --units`"*. A range is a *predicate over a
  space whose forbidden positions are invisible* (§1 c): whether `1-4` names a
  mirror depends on whether an earlier file carried a BOM. The user then meets
  a rejection they could not have predicted from what they typed, on a command
  whose *other* failure mode is irreversible. Every disposition is bad — reject
  the whole range (unpredictable), skip the mirror (the range stops meaning what
  it says, and worse: the skipped mirror may **ride anyway** via D70 promotion
  if the range completes the file, so one unit is simultaneously
  not-selectable-by-id and disclosed — exactly the confusion D70 spent a record
  avoiding by keeping mirror inclusion *derivation, not selection*), or include
  it (violates spec line 92 verbatim).
- **A range is the notation most likely to silently complete a file, and
  completing a file is a category change** (§1 e). An off-by-one in a comma
  list discloses one wrong unit — D67 §2.1's stated harm, and the harm the
  snippet exists to catch. An off-by-one at a range's upper bound discloses
  `file_salt` and `s_root`, i.e. hands the recipient the offline full-file
  confirmation oracle spec line 95 is written to deny them. The consent gate
  catches it; that is an argument for not multiplying the ways to arrive there,
  not for adding one.
- **Ranges alone can express an unbounded expansion.** A comma list's size is
  bounded by `ARG_MAX`; `--units 0-18446744073709551615` is 26 characters and
  expands to 2⁶⁴ ids. A range parser therefore needs its own pre-allocation cap
  and its own error class — a genuine new parser-hardening obligation (working
  principle 2) that the comma list simply does not have. This is the one place
  the arm is not free, and it is the place it claimed to be.

**Direction of regret is asymmetric.** Accepting more syntax later is
backward-compatible; a `3-5` that means something today can never be un-meant.
The ergonomic case ranges would serve — hundreds of `--split` units — is
already served without new grammar: `--all`, whole-file reveal, the repeated
flag (§1 g), and shell expansion (`--units $(seq -s, 10 40)`).

### 2.2 "Comma list, because the spec example says so" — refused as a *reason*, while its *conclusion* stands

The register's ground is defeated by spec line 149's own `…` (§1 a). The
conclusion survives on §2.1. This is recorded rather than glossed because a
ruling that keeps a conclusion must not keep a broken argument with it: if
v1.1 revisits ranges, the thing to re-measure is the mirror-interleaving and
promotion risk, **not** whether the spec printed a comma.

### 2.3 "The default filename is a trivial pick" — overturned

Three measurements break the framing.

- **The obvious friendly choice is a security defect.** Spec line 36's own
  example (`-o pitch.sealproof`) visually suggests a human-meaningful stem, and
  the manifest holds exactly one human-meaningful string: the title. §1 (k)
  measures it as unbounded, unvalidated, user-controlled UTF-8. A
  title-derived default is (i) **path injection** — `/`, `..`, NUL, newline,
  and leading `-` all live in the accepted set; (ii) **unbounded** against
  `NAME_MAX`; (iii) **audience widening** — the title is recipient-visible *by
  design and with a warning*, but a filename travels as a mail-attachment name,
  a backup-index entry, a cloud-sync metadata field and a screenshot, none of
  which the seal-time warning covered. A source-path-derived name is strictly
  worse: unrevealed files' paths are withheld by construction (spec line 95 —
  *"bundle recipients see unrevealed files only as committed placeholders"*), so
  a name built from one would disclose precisely what the bundle refuses to.
- **Neither precedent transfers** (§1 i, j), so the pick cannot be made by
  citation.
- **The load-bearing clause is an ordering rule, not a name** (§3 R6). A
  filename-only framing cannot reach the question of whether the collision is
  detected before or after the irreversible-disclosure consent.

### 2.4 The arm nobody supplied — a selection-derived name suffix — also refused

`antseal-reveal-<work-id>-<8 hex of a selection digest>.sealproof` would make
distinct selections land on distinct paths, bounded and closed-alphabet, and
looks like it dissolves the collision. Refused:

- It mints a **new derived value** with a domain-separation question of its own
  (digest over *which* set — the typed ids, the resolved normal units, or the
  post-promotion set including riding mirrors?), and a wrong answer maps two
  different disclosures to one name. Derived values in this project get domain
  tags and golden vectors; that is real cost for a filename.
- It does not help the human. `…-a3f19c02.sealproof` and `…-7b2e5510.sealproof`
  are indistinguishable at the moment that matters — attaching one to an email.
  The collision *error* was the useful signal; the suffix deletes it.
- It reintroduces the proliferation harm §3 R7 refuses the timestamp for.

---

## 3. The ruling

Eleven rules. R1–R4 are half 1; R5–R11 are half 2.

**R1 — The `--units` value grammar is a comma-separated list of decimal
work-global unit ids, and is exactly the shipped parser.**
`#[arg(long, value_delimiter = ',', value_name = "UNIT")] pub units: Vec<u64>`
(`cli.rs:371-374`) is **ratified verbatim**; no clap attribute changes. The
grammar is: one or more decimal `u64` ids, separated by `,`, with no whitespace,
no sign requirement, no radix prefix, no ranges, no negation, no wildcards. Ids
are **0-based** (§1 b) and are the ids `show` prints — the surface spec line 149
designates *"the preview for `reveal --units`"*.

**R2 — The acceptance envelope, recorded so the frozen snapshot cannot drift by
accident.** These are consequences of R1's parser, each measured in §1 (g), each
deliberately kept:

| input | disposition | why it is kept |
| --- | --- | --- |
| `--units 3,5` | accepted → `[3, 5]` | the spec's example (line 36) |
| `--units 3 --units 5` | accepted → `[3, 5]` | clap `Append`; a harmless superset, and the only ergonomic escape from `ARG_MAX` |
| duplicate ids (`3,3,5`) | accepted; R16 dedups | R16's shipped rule (`pipeline/reveal.rs:181-184`); a duplicate is a typo with no disclosure consequence |
| `+3` | accepted ≡ `3` | Rust `u64::FromStr`; refusing it would mint a custom parser for zero safety gain |
| `--units` with no value, `''`, `3,,5`, `3,5,` | clap usage error, exit 2 | empty ids are never a selection |
| `0x3`, ` 3`, `3-5`, `3..5` | rejected | not the grammar |
| ids ≥ the work's unit count | parse-accepted, resolution-rejected `UnknownUnitId` | id validity is manifest-relative, not lexical |
| a mirror's id | parse-accepted, resolution-rejected (§1 d) | spec line 92's guard belongs where the manifest is known |

The two-layer split is normative: **the parser validates lexis only; every
manifest-relative judgment stays in R16's resolution**, which is where the ids,
the kinds, and the typed errors already live.

**R3 — Range notation is refused for MVP, and the refusal must be legible.**
A `--units` value that fails `u64` parsing **and** contains `-` or `..` between
digits gets a message naming the supported form rather than clap's generic
digit error. Required copy content (exact spelling is U31/R18's domain, not
this record's): the offending value, the fact that ranges are not supported,
the comma form, and a pointer to `show`. Implemented as a `value_parser` on the
`units` arg that parses `u64` and, on failure, discriminates the range-shaped
case — no other clap attribute moves, so `--units 3,5` keeps its shipped
behaviour byte-for-byte. **This is the one behavioural change R1's ratification
requires, and it is a frozen-snapshot event** (U1's help text gains nothing;
only the error path changes — but the tamper/usage fixtures do).

**R4 — v1.1 reservation costs nothing and is recorded, not built.** No syntax,
key, flag, or error code is reserved for ranges. Nothing needs to be: the
grammar is a CLI-local lexical rule with zero wire footprint (no bundle key, no
manifest field, no HKDF label, no domain tag, nothing for Q14/F4), so a v1.1
range syntax is a pure parser addition over an unchanged resolution layer. The
two things a future range decision must re-measure are named in §2.2. Adding
syntax later is compatible; this record's refusal costs the future nothing.

**R5 — The default output path.**

```text
template:  ./antseal-reveal-<work-id>.sealproof
example:   ./antseal-reveal-7c1d5b8e0a3f9264e8b7415c23d0af965e1c7b4098f2a6d3b45e0c179a2d6f83.sealproof
```

- **Location: the invocation cwd**, exactly as D48 §1. Not a subdirectory —
  `reveal` produces one file, and `-o` is typed `FILE` (`cli.rs:384`), so a
  directory default would contradict the flag's own type.
- **Stem: `antseal-` + the command name + `-` + the discriminant.** This is the
  house pattern both existing defaults follow (`antseal-restore-<work-id>/`,
  `antseal-vault-export-<timestamp>.sealvault`), so a user who has seen one can
  predict the others and a directory listing groups every antseal artifact.
- **Discriminant: the `work_id` in D29's printed form** — 64 lowercase hex via
  the existing `hex32` (`pipeline/restore.rs:1000-1007`), the same rendering
  D48's directory name uses. Work-scoped, so the default never collides
  *across* works.
- **Bounded by construction: 15 + 64 + 10 = 89 bytes**, under `NAME_MAX` on
  every supported platform with room to spare. The variable part's alphabet is
  closed: `[0-9a-f]`.
- **No extension coercion on an explicit `-o`.** `-o pitch.txt` writes
  `pitch.txt`. Silently rewriting a user's path is the class of surprise D48 §2
  exists to prevent; spec line 36's `-o pitch.sealproof` shows the user
  supplying the extension themselves.
- **Identical in every mode.** `--json` does not change or suppress the default
  (a mode-dependent default would be exactly the human/machine divergence D51
  works to remove); the resolved path is always reported — U28's closing line
  and its `--json` document both carry it.

**R6 — Content in the name: `work_id` only, and the reason is a boundary, not a
taboo.** The test is **not** "is it content-derived" — it is *does the name
disclose to a wider audience than the artifact it names?* A filename's audience
(mail relays, backup indexes, sync metadata, screenshots, shell history) is
strictly wider than the bundle's. Under that test:

- **`work_id` passes.** Every bundle embeds the plaintext manifest bytes (spec
  line 114) and `work_id = SHA-256(manifest body)`, so anyone holding the file
  already has it; D48 already puts it in a directory name. The name discloses
  nothing the artifact does not.
- **The title fails, the source paths fail** — §2.3, on the free-form-title
  measurement (§1 k) and on spec line 95's withheld-path guarantee.
- **A reveal timestamp fails** — R7.

**This is D67's principle transposed, and saying which part binds matters.**
D67's *subject* (a consent screen's display integrity) does **not** bind: a
filename is not read by the user as a warranty and cannot repaint a prompt.
D67's *principle* does: **user-controlled bytes must never become control
surface**, and the remedy is the same shape — a closed alphabet fixed by the
ruling rather than an escape/sanitize pass over whatever the user typed. D67
closed the escape set so a crafted file could not repaint the screen; D68
closes the name's alphabet so sealed content cannot author a path. Genuinely
different: D67's field is content the user is *about to disclose anyway*, so
its cost was bounded; a filename is disclosed to an audience that never
consented to anything, which is why the answer here is exclusion rather than
escaping.

**R7 — Collision: refuse. Never overwrite, never suffix, never timestamp,
never prompt.** An existing target — file, directory, symlink, anything
`symlink_metadata` reports — is a typed error naming the path and pointing at
`-o`; nothing is written and no byte of the existing file is touched.

- **Overwrite** violates the standing "never silently clobber" mandate D48 was
  written under, and the destroyed artifact is worse than a restored file: it
  is a bundle the user may already have sent and may need to send again, and
  §1 (j) says rebuilding it may not reproduce it.
- **Byte-aware skip** (D48 §3) is unavailable — §1 (j).
- **Prompting** is refused twice over: D48 §5 already ruled that the overwrite
  policy *replaces* the interactive "overwrite? y/n" convention, and `reveal`
  has exactly one consent prompt (U29's disclosure gate, registered under D51's
  matrix). A second prompt in the same command dilutes the one that carries the
  irreversible decision.
- **Auto-suffix / timestamp** is the departure from U12, and it is argued, not
  assumed. An **export is a backup you deliberately keep many of and identify
  by date**; a **proof bundle is an artifact you send exactly one of and
  identify by what it discloses** — which a timestamp does not say. A default
  that quietly emits `…-2.sealproof` multiplies near-identical irreversible
  disclosures on disk and invites sending the wrong one. A timestamp
  additionally stamps *when you revealed* into a name that travels as an
  attachment; reveal-time is not otherwise in the bundle (the anchors' fetch
  dates are artifact-fetch times, `bundle/schema.rs:444-495`), so it is a small
  new leak by R6's audience test.
- **Refusal makes the default name unambiguous by construction**, which is the
  positive result and the reason it beats every suffixing scheme: at most one
  bundle per work can ever hold the default name, so a user's default-named
  file is never one of two similar candidates. In particular a `--include-receipt`
  bundle (which exposes the paying wallet, spec lines 36/110) can never sit
  beside a plain one under confusable default names.
- **The error class** is a local, user-fixable conflict — the same rung D48 §6
  gives `refused-overwrite`, below evidence problems and above transient
  network ones. **U2 owns the number**; D68 fixes the class and its rank only.
  (D69 owns `verify`'s verdict mapping and is untouched here.)

**R8 — Ordering: the output path is resolved and checked FIRST — before the
preview, before consent, before any fetch.** `MVP-SPEC.md` line 34 states the
house's normative order for `seal`: *"Normative order puts every cheap,
failable step **before** the one irreversible paid one."* `reveal`'s
irreversible step is the disclosure consent (spec line 36: *"irreversibly
disclosed"*). So the sequence is:

```text
resolve -o / default  →  check target absent  →  [R16 prepare: gather, decrypt]
   →  R15 preview  →  U29 consent gate  →  R13 build  →  exclusive write
```

Three consequences, all deliberate: a user is **never** asked to consent to an
irreversible disclosure that then cannot be written; a refused-overwrite costs
zero network fetches and zero money; and the failure arrives while the user is
still thinking about the command, not after they have committed to it. This
composes with R16's shipped two-phase `prepare → build` seam (`tasks/R.md` R16
execution note: *"U29's gate sits between preview and build with nothing
bundle-shaped before consent"*) — R8 adds one earlier, cheaper gate in front of
it.

**R9 — Write discipline: exclusive creation, not temp-and-rename.** The file is
created with `create_new(true)` (O_EXCL) at the final path, written, flushed,
and closed; on any write error the partial file is removed. The requirement here
is **exclusivity**, not atomic replacement — D48 §4's temp+rename exists to make
"this file was restored and verified" all-or-nothing against a *replacement*,
whereas a rename here would defeat R7 by clobbering. R8's pre-flight check is
advisory (TOCTOU); `create_new` is what makes "never overwrite" true rather than
intended. **Recorded residual:** a hard kill mid-write leaves a partial
`.sealproof` at the final path, which then refuses the next default-named run
until the user removes it or passes `-o`. That failure is safe and
self-announcing — a truncated bundle is a malformed bundle and `verify` rejects
it loudly — and it is preferred over any rename-based scheme that could replace
a good bundle.

**R10 — Home: one computation, beside D48's.** A new `reveal_out` module in
`antseal-cli`, mirroring `restore_out.rs:56-68` exactly:

```rust
pub const BUNDLE_FILE_EXTENSION: &str = "sealproof";
pub const BUNDLE_FILE_PREFIX: &str = "antseal-reveal-";
pub fn default_bundle_path(work_id: &[u8; 32]) -> PathBuf;
```

`BUNDLE_FILE_EXTENSION` is **minted here** — §1 (l) measures that the repo has
210 uses of `.sealproof` and not one constant, while `.sealvault` has
`EXPORT_FILE_EXTENSION` (`vault/export.rs:185`). One home means U28 and any
future caller (a v1.1 `reveal --split-per-counterparty`, the M4 drill scripts)
share it. `antseal-core` gains nothing: this is CLI-side policy, `seal-core`'s
WASM safety is untouched because `seal-core` is untouched.

**R11 — What pins it.** Four pins, all U28's to land except the last:

1. A unit test asserting the exact worked example of R5 from a fixed
   `[u8; 32]`, referencing `BUNDLE_FILE_EXTENSION` rather than the literal —
   the `default_export_name_is_timestamped_and_extension_advisory` model
   (`commands.rs:584-587`).
2. A collision test: default path exists → refused, **nothing written**, the
   existing file's bytes and mtime unchanged, and the refusal observed
   **before** the consent gate fires (assert the gate was never asked).
3. A `--units 3-5` test asserting R3's message class by **message content**,
   not by exit code — a bare digit error also exits 2.
4. The `cli-surface.help.txt` snapshot re-freeze for reveal's `-o` line, which
   must name the default as restore's and export's already do (§1 h).

---

## 4. Refused shapes

| shape | refused on |
| --- | --- |
| range syntax `3-5` / `3..5` in MVP | mirrors sit at positions invisible in the notation (§1 c) and every disposition of a mirror-spanning range is bad (§2.1); a range is the notation most likely to silently complete a file, and completion is a category change in disclosure (§1 e, spec line 95); ranges alone can express an unbounded expansion (§2.1) |
| "comma list because the spec example says so" | line 149's canonical list spells the value `…` and expressly calls line 36 an example (§1 a) — the conclusion stands, the reason does not (§2.2) |
| space-separated `--units 3 5` | would need `num_args(1..)`, which makes the positional `<WORK-ID>` ambiguous after the flag; the repeated flag already covers the need (§1 g) |
| whitespace/radix tolerance (`0x3`, `' 3'`) | mints a custom integer parser for zero safety gain; ids come from `show`'s output, not from prose |
| moving mirror rejection into the parser | the parser cannot know the manifest; the two-layer split (R2) keeps every manifest-relative judgment in R16 where the typed errors already live (§1 d) |
| a title-derived default filename | unbounded, unvalidated, user-controlled text authoring a path — injection, `NAME_MAX`, and audience widening past the seal-time warning (§1 k, §2.3) |
| a source-path-derived default filename | discloses exactly what the bundle withholds — unrevealed files are committed placeholders (spec line 95) |
| a timestamped default (U12's mechanism) | multiplies near-identical irreversible disclosures on disk; stamps reveal-time into a travelling name, a small new leak by R6's audience test (§3 R7) |
| numeric auto-suffix (`-2`, `-3`) | same proliferation harm; deletes the collision signal that was the useful output |
| selection-digest suffix | mints a new derived value with its own domain-separation question, indistinguishable to the human at the moment that matters, same proliferation harm (§2.4) |
| overwrite on collision | destroys a bundle that may already have been sent and may not be reproducible (§1 j) |
| D48 §3's byte-aware skip | structurally unavailable: the anchor set legitimately drifts under the every-invocation upgrade hook (§1 j) |
| an "overwrite? y/n" prompt or a `--force` flag | D48 §5 already replaced that convention; a second prompt dilutes U29's irreversible-disclosure gate (D51's registry) |
| collision checked after the consent gate | inverts spec line 34's normative order onto the wrong step (§3 R8) |
| temp file + rename (D48 §4's mechanism) | a rename clobbers, defeating R7; the requirement here is exclusivity, not atomic replacement (§3 R9) |
| `-o -` (stdout) | bundles are binary and `--json` owns stdout under D51 |
| appending/rewriting an extension on an explicit `-o` | silently rewriting a user's path is D48 §2's class of surprise; spec line 36 shows the user supplying it |
| a default that differs under `--json` | reintroduces the human/machine divergence D51 removes |

---

## 5. Edges, drawn explicitly

**D68 / D48.** D48 owns `restore`'s output policy and keeps it unchanged. D68
takes D48's *principles* (work-scoped default, never silently clobber, no
prompts, class-before-number) and **explicitly departs from two of its
mechanisms** — byte-aware skip (unavailable, §1 j) and temp+rename (defeats
exclusivity, R9) — each with its measurement. Nothing in D48 is amended.

**D68 / U12.** U12's timestamped `.sealvault` name stands untouched for
exports. R7 records why `reveal` does not follow it. If a future decision wants
one rule for both, this record is where the distinction lives.

**D68 / D67.** D67 owns the *snippet value and rendering* in the preview; D68
owns *the path the resulting bundle is written to*. They meet only at R6's
transposition of D67's principle (user bytes never become control surface) and
at R8's ordering, which guarantees the preview D67 governs is never rendered for
a disclosure that cannot land.

**D68 / D70, D28.** Untouched. D70's promotion rule and D28's full-reveal
strictness are *inputs* to §2.1's refusal of ranges, not outputs of it. This
record adds no mirror or promotion semantics.

**D68 / D69, D65.** D68 fixes the **class** of the output-collision failure and
its severity rank (R7); the **number** is U2's and the `--json` field carrying
it is the D65/U50 family's. D69's subject is `verify`'s verdict-to-exit mapping
and cannot collide with this. R16's `RevealError` variants remain unmapped to
exit codes by this record, exactly as R16's execution note left them.

**Wire surface: zero.** No bundle key, no manifest field, no HKDF label, no
domain tag, no registry slot, nothing for Q14/F4 (`docs/format/registry-v1.md`
is untouched and no change is requested). Both halves are CLI policy, changeable
in a future app version without a format bump — the same status D48 recorded for
itself. The one frozen artifact this touches is `cli-surface.help.txt`, which is
a snapshot, not a format.

---

## 6. Consumed rows and inputs

- **U28** (`tasks/U.md:475-486`) — both "per open decision 12" references
  discharged.
- **U1** (`tasks/U.md:8-20`) — owns the clap surface and the help snapshot;
  R3 and R11 (4) are its amendments.
- **U29, U2, R16, R15** — the consent gate, the exit-code table, the reveal
  library API, the preview computation.
- **`MVP-SPEC.md`** lines 34, 35, 36, 76, 92, 95, 112, 114, 149.
- **D48** (the sibling output policy and its principles), **U12** (the departed
  precedent), **D67** (the transposed principle), **D70 / D28** (promotion and
  full-reveal strictness), **D51** (prompt-class matrix), **D29** (printed hex
  form), **D23** (mirror is the file's last unit), **D43** (cache-first
  sourcing, via R16), **D34** (CLI-side placement).
- Measured code: `crates/antseal-cli/src/cli.rs`,
  `crates/antseal-cli/src/restore_out.rs`,
  `crates/antseal-cli/src/pipeline/reveal.rs`,
  `crates/antseal-cli/src/pipeline/restore.rs`,
  `crates/antseal-cli/src/preview.rs`,
  `crates/antseal-cli/src/commands.rs`,
  `crates/antseal-cli/src/vault/export.rs`,
  `crates/antseal-cli/src/run.rs`,
  `crates/antseal-core/src/content/unit.rs`,
  `crates/antseal-core/src/content/mirror.rs`,
  `crates/antseal-core/src/manifest/error.rs`,
  `crates/antseal-core/src/bundle/schema.rs`,
  `crates/antseal-cli/tests/snapshots/cli-surface.help.txt`,
  `crates/antseal-cli/tests/cli_surface.rs`.

---

## 7. Registrar's edit set

**This lane wrote one file: this one.** Everything below is instruction.

1. `TODO.md` decision register, D68 line (Due M3 block) — replace with the
   resolved line in the lane's closing report (D67's line is the model).
2. `docs/decisions/README.md` — one index row for this record, in id order,
   status/date from this record's own `- **Status` / `- **Date` lines (D119
   conventions).
3. `tasks/U.md` **open decision 12** — mark RESOLVED (D68) in the house form
   used by decisions 1–11 and 14–15 of that list.
4. `tasks/U.md` **U28** — apply §8.1 (a `Do` amendment, two new `Accept` rows,
   and a `Notes` line).
5. `tasks/U.md` **U1** — append §8.2.
6. **Rows/ledger**: one row candidate and two ledger candidates are described
   in §9; the registrar assigns any ids.
7. **No edits** to `MVP-SPEC.md`, `docs/format/registry-v1.md`, any decision
   record, any code, or any fixture are requested by this ruling. The
   `cli-surface.help.txt` snapshot changes when **U28** lands, not now.

---

## 8. Quoted entry notes (registrar's to apply)

### 8.1 `tasks/U.md` U28

**Replace in `Do`** — *"parse selection (`--all` | `--units` comma list per open
decision 12; …"* → *"per **D68**"*; and *"write the bundle to `-o file` (default
name per open decision 12)"* → *"write the bundle to `-o file`, default
`./antseal-reveal-<work-id>.sealproof` per **D68**"*.

**Append two `Accept` rows:**

> - default output path is `./antseal-reveal-<work-id>.sealproof` (D68 §3 R5,
>   worked example pinned by a unit test referencing `BUNDLE_FILE_EXTENSION`);
>   an existing target is **refused with nothing written**, the existing bytes
>   and mtime unchanged, and the refusal fires **before** the U29 consent gate
>   and before any ciphertext fetch (test asserts the gate was never asked)
> - `--units 3-5` is rejected by a message naming the comma form and `show`
>   (asserted **by message content**, not exit code — a bare clap digit error
>   also exits 2)

**Append `Notes`:**

> - Notes: **[D68, 2026-08-12]** Both halves ruled by
>   docs/decisions/D68-units-syntax-and-default-bundle-filename.md. **Syntax**:
>   the shipped `--units` parser (`value_delimiter = ','`, `Vec<u64>`,
>   `cli.rs:371-374`) is ratified verbatim — comma list only, 0-based
>   work-global ids, ranges refused for MVP (mirrors sit at positions invisible
>   in range notation, and a range's off-by-one promotes a file to a full reveal
>   under D70/D28, disclosing `file_salt`/`s_root`); the parser validates lexis
>   only and every manifest-relative judgment stays in R16's resolution.
>   `RevealError::EmptySelection` is **unreachable from the CLI** (clap kills
>   every empty spelling first) — do not spend an Accept row on it.
>   **Filename**: `./antseal-reveal-<work-id>.sealproof` in the invocation cwd,
>   work-id in D29's 64-lowercase-hex form via `hex32`, closed `[0-9a-f]`
>   alphabet, 89 bytes by construction; **never** title- or source-path-derived
>   (free-form unbounded user text authoring a path). Collision = refuse
>   (never overwrite/suffix/timestamp/prompt); resolve and check the path
>   **first**, per spec line 34's normative order; write with
>   `create_new(true)` (exclusivity, not temp+rename — a rename would clobber),
>   removing the partial on write error. Home: a new `reveal_out` module beside
>   `restore_out.rs`, minting `BUNDLE_FILE_EXTENSION` (the repo has 210 uses of
>   `.sealproof` and no constant). Error **class** is D68's (D48 §6's
>   `refused-overwrite` rung); the **number** is U2's. `-o` is taken verbatim
>   — no extension coercion; the default is identical under `--json`.

### 8.2 `tasks/U.md` U1 — append a `Notes` line

> - Notes: **[D68, 2026-08-12]** The `reveal` arg surface is ratified as shipped
>   (docs/decisions/D68-units-syntax-and-default-bundle-filename.md §3 R1–R2):
>   no clap attribute on `--units` changes. Two amendments land with U28, both
>   re-freezing `cli-surface.help.txt`: (i) a `value_parser` on `units` that
>   discriminates range-shaped values (`3-5`, `3..5`) and rejects them with a
>   message naming the comma form and `show`, replacing clap's generic
>   `invalid digit found in string`; (ii) reveal's `-o <FILE>` help line must
>   name its default, as restore's `-o <DIR>` and `vault export`'s `[FILE]`
>   already do (snapshot lines 241 and 361 vs 279-280).

---

## 9. Discovered work — described, not registered

No ids are minted here.

**(i) `--units 3-5` has no legible rejection today — row-shaped.** Measured in
§1 (g): the shipped binary answers `error: invalid value '3-5' for '--units
<UNIT>': invalid digit found in string`. The spec's own example is a comma list
(line 36) and unit ids are printed by `show` as a column of consecutive
integers, so a user reaching for a range is the expected mistake, not an exotic
one. §3 R3 rules the fix and §8.1 gives U28 the Accept row; if the registrar
prefers it tracked separately from U28, it is a product row (it changes what a
user sees), not a ledger line.

**(ii) `RevealError::EmptySelection` is unreachable from the CLI — ledger.**
`pipeline/reveal.rs:272-275` documents it as *"`--units` was given with no
ids"*, but clap rejects every empty spelling first (§1 g). The variant is
correct as a library-API defensive arm — R16 is a library API with non-CLI
callers by design — but the doc comment describes a CLI path that cannot exist.
Doc-prose accuracy only; §8.1's note is the practical warning.

**(iii) The `.sealproof` extension has 210 uses and no constant — ledger (or
folded into U28).** §1 (l). `.sealvault` has `EXPORT_FILE_EXTENSION`
(`vault/export.rs:185`); `.sealproof` is spelled as a literal in every test that
names a bundle file. §3 R10 mints the constant as part of U28; the pre-existing
literals in `crates/antseal-cli/tests/*.rs`,
`crates/antseal-core/tests/*.rs` and `crates/antseal-cli/src/machine.rs:287`
are not required to migrate by this ruling, and are recorded here so a future
tidy-up has a starting list rather than a search.

**(iv) One question for the maintainer, recorded so the ruling does not
silently answer it.** *(**Answered 2026-08-12: `antseal-reveal-`** — see
"Amendment — the §9 (iv) filename-stem question, answered 2026-08-12" below.)* R5 picks `antseal-reveal-` for house consistency with
`antseal-restore-` and `antseal-vault-export-` (stem = command name). The
alternative reading is that the stem should name the *artifact* rather than the
*command* — `antseal-proof-<work-id>.sealproof`. Nothing in this record depends
on which is chosen: swap the `BUNDLE_FILE_PREFIX` constant and R11's example
test, and every other rule stands unchanged. Recorded as a naming preference,
not an open decision.

---

## Outcome

The register filed half 1 as settled by the spec's example and half 2 as a
trivial pick. Measurement reversed the standing of both.

Half 1's **conclusion survives and its argument does not**: line 149's canonical
list spells the value `…` and expressly calls line 36 an example, so the
spec-example ground is empty — while the id space supplies a much better one.
Ids are dense and gapless, so a range is arithmetically well-posed; but raw
mirrors are interleaved into that space at positions determined by invisible
file properties, and D70's promotion turns a range's off-by-one from "one wrong
unit" into "this file's `file_salt` and `s_root`", the exact offline
confirmation oracle spec line 95 is written to deny. Ranges are refused for
MVP on that, at zero cost to a v1.1 that wants them. What the ratification
surfaced is that the shipped parser already answers the syntax question and the
only thing genuinely missing is a legible *refusal* — the message a user meets
when they type the thing the spec's own example invites.

Half 2 is overturned outright. The friendly-looking default — a title-derived
name — is a path-injection and audience-widening surface over free-form
unbounded user text; the two in-house precedents disagree and neither transfers,
because reveal's output is a function of an anchor set designed to change,
not of immutable sealed content; and the ruling's load-bearing clause turns out
not to be the name at all but the **order**: check the path before asking for
consent, so nobody is ever asked to make an irreversible disclosure that then
cannot be written. The name itself ends up boring on purpose — cwd, house
prefix, 64 hex characters, one extension, 89 bytes, refuse on collision — which
is what a name should be once the interesting parts have been ruled somewhere
they can be seen.

---

## Amendment — the §9 (iv) filename-stem question, answered 2026-08-12

**Authority**: the maintainer, in session 2026-08-12, answering the one question
§9 (iv) recorded so the ruling would not silently settle it. **Same-act
disclosure (D117 §2.1 (c))**: this section lands in the same act as the record
it amends. It adds no ruling — it closes a recorded question at the value §3 R5
already picked.

The question, quoted verbatim from §9 (iv):

> R5 picks `antseal-reveal-` for house consistency with `antseal-restore-` and
> `antseal-vault-export-` (stem = command name). The alternative reading is that
> the stem should name the *artifact* rather than the *command* —
> `antseal-proof-<work-id>.sealproof`.

**Answer: `antseal-reveal-`.** The default output path is therefore

```text
./antseal-reveal-<work-id>.sealproof
```

exactly as §3 R5 and §5's worked example render it, and
`BUNDLE_FILE_PREFIX = "antseal-reveal-"` in §3 R10 is the ruled value rather
than a provisional one. The command-name reading wins: a user who has seen
`antseal-restore-<work-id>/` or `antseal-vault-export-<timestamp>.sealvault` can
predict this one, and a directory listing groups every antseal artifact under a
single prefix.

**Which rulings stand**: all of them, unchanged. §9 (iv) already recorded that
*"nothing in this record depends on which is chosen"* — the swap would have
touched `BUNDLE_FILE_PREFIX` and R11's example test and nothing else — so this
answer moves no rule, no Accept row and no refused shape. The 89-byte bound in
§3 R5 is computed from this stem (15 + 64 + 10) and is confirmed by the answer
rather than changed by it.
