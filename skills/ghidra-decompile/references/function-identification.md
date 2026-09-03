# Function identification and external signatures

## Contents

- When to search
- Discover applicable resources
- Qualify the source
- Use Ghidra Function ID conservatively
- Inspect analyzer-excluded candidates
- Record and verify results
- DOS and Win16 example

## When to search

Before broad manual naming, actively look for compatible Function ID databases,
signature sets, debug symbols, map files, source archives, and already-analyzed
reference binaries. This is especially valuable when a native executable
statically links a substantial compiler runtime, standard library, middleware,
codec, or platform SDK.

Search after establishing the program format, processor language, address model,
compiler family, likely compiler version, and packing or overlay status. Do not
spend a campaign rediscovering known library code one routine at a time.

Skip the search only when the binary already has authoritative symbols, the
suspected library code is outside the campaign scope, or no compatible corpus
can be found. Record the reason in campaign evidence.

## Discover applicable resources

Build a compatibility tuple from the target before searching: executable or
object format, processor language, bitness, operating environment, compiler
family and likely version, memory model, and known library or middleware names.
Search for each evidenced component rather than using one generic signature
collection for the whole program. Useful sources include Ghidra Function ID
databases, other tool signature packs that have a documented conversion path,
vendor symbols and maps, compiler library archives, SDKs, source releases, and
previously analyzed binaries with verified byte-equivalent functions.

Check current upstream documentation and inventory when network access is
available. A candidate is applicable only when its documented inputs overlap the
target's compatibility tuple. Do not use a DOS or Win16 database for a protected
mode DOS extender, a different processor language, or an unsupported memory
model merely because the compiler family matches.

Record both accepted and rejected candidates in `evidence.jsonl`, including the
query or catalog used to find them and the compatibility evidence behind the
decision. This keeps resource discovery reproducible and stops later turns from
repeating the same search.

## Qualify the source

Prefer sources in this order when they are compatible with the target:

1. symbols or map files shipped for the exact binary;
2. vendor or project source and libraries for the exact release;
3. Ghidra-provided databases and documented processor analyzers;
4. reproducible databases built from identified original libraries;
5. curated third-party signature databases;
6. adjacent compiler or library versions used only for corroboration.

For every external source, establish and record:

- its URL, immutable release or commit, and SHA-256 digest;
- its license and whether local use or redistribution is permitted;
- the database generator and Ghidra version when known;
- processor language, bitness, memory model, object format, compiler family,
  compiler version, and library variants represented;
- the target evidence supporting compatibility, such as compiler strings,
  runtime error text, object conventions, startup shape, or release chronology.

Inspect the source's current documentation and inventory. Do not assume that a
repository name, old result, or nearby compiler date proves compatibility. Keep
downloaded databases outside managed Ghidra installations and outside the
reusable skill directory; do not vendor them into this repository without
explicit user intent and a compatible license.

When a project has no immutable releases or published checksums, pin the source
commit and calculate the selected artifact's SHA-256 digest after download. A
Git object ID is not an artifact checksum. Treat a missing or nonstandard license
as a use constraint and do not redistribute the database unless its terms permit
it.

## Use Ghidra Function ID conservatively

1. Confirm the exact active project and program, analysis-idle state, binary
   identity, language, and save state.
2. Capture baseline function and default-name counts before running Function ID.
3. Query or attach only the strongest compatible database first. Prefer a
   read-only query when the available tooling supports it. If attachment is
   required, record the database, attachment scope, and analyzer configuration;
   run the Function ID analyzer without unrelated reanalysis.
4. Review normal Function ID results before applying names. Preserve stronger
   user-defined symbols and route conflicts for manual review. Measure each
   candidate database in isolation before combining compatible databases.
5. Apply only a bounded coherent batch, then independently read back every
   changed address and inspect representative callers and decompilations.
6. Save only after verification. Record baseline and final counts, conflicts,
   ambiguous candidates, and unmatched runtime regions.

Treat database attachment as analyst-environment state. Inventory existing
attachments before adding one, do not remove databases owned by another
campaign, and record any campaign-added attachment that remains active.

An exact database match identifies compiled library code; it does not establish
the target program's higher-level behavior. Keep runtime/library naming separate
from game-specific behavior recovery and from semantic-parity claims.

Use nearby compiler versions as a comparison set, not as permission to import
their version-specific names. Agreement across versions can corroborate a
generic helper identity, while disagreement is evidence to remain conservative.

## Inspect analyzer-excluded candidates

Normal Function ID scoring can omit short functions, weakly linked records, or
otherwise exact hashes that do not meet its scoring threshold. When unresolved
library coverage matters, use a read-only query to inspect full and specific
function hashes in the best-matching database.

- Treat a unique exact hash as cross-binary evidence, not sufficient proof by
  itself. Verify instructions, ABI, callers, constants, and data flow.
- If a hash returns multiple records, keep the function unresolved unless other
  independent evidence selects one candidate.
- Prefer the more discriminating specific-hash result when full-hash candidates
  collide, but still verify semantics and compatibility.
- Object-module membership and ordering between uniquely identified neighbors
  may corroborate internal library routines. Proximity alone never authorizes a
  name.
- Do not lower global analyzer thresholds merely to make the result count rise.

## Record and verify results

For every accepted match, retain enough evidence to reproduce the decision:

- target program identity and function address;
- database identity, compiler/library version, and source revision or digest;
- match method, including normal Function ID, full hash, specific hash, or
  object-module context;
- candidate count and any material competing names;
- instruction or byte agreement and independent semantic evidence;
- applied name, confidence, batch ID, verifier, readback result, and save state.

Put match claims in `evidence.jsonl` and applied names in `renames.jsonl`. Summarize
database provenance, coverage, conflicts, and rejected alternatives in
`ARCHITECTURE.md`. A large match count, or zero remaining `FUN_*` names, does not
replace the completion audit.

## DOS and Win16 example

For 16-bit DOS and Windows x86 programs built with vintage Borland or Microsoft
C/C++ compilers, evaluate
[moralrecordings/ghidra-fidb-dos-win16](https://github.com/moralrecordings/ghidra-fidb-dos-win16)
during the compiler/runtime audit. Inspect its current README, database inventory,
license, and revision before use.

The repository currently provides prebuilt databases for Borland C++ 2.0 through
3.1, Microsoft C 3.0 through 6.0, Microsoft C/C++ 7.0, and Microsoft Visual C++
1.52c. It does not publish GitHub releases, so pin a commit and hash only the
selected `.fidb` file. Its nonstandard license includes field-of-use restrictions;
verify that the intended use is permitted and do not copy its databases into this
skill or a managed Ghidra installation.

Select the database matching the evidenced compiler version and target language
first. Compiler copyright strings, distinctive runtime errors, startup code,
memory-model conventions, and the executable's release window are useful
corroboration. Do not attach every database indiscriminately or infer an exact
compiler solely from the program's release year. Compare adjacent versions only
after the best candidate has been measured in isolation. Although the upstream
README recommends attaching every bundled database, use that as operating
documentation rather than a target-selection rule; isolated measurements make
conflicts and false attribution easier to audit.
