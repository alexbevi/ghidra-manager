# The Function Was There All Along: Recovering a DOS Game's Dialogue Handlers in Ghidra

*A reverse-engineering story about function-pointer tables, false non-returning calls, and the moment 2,304 bytes of "data" turned into 47 navigable functions.*

> **Lab notes.** The addresses and measurements in this article come from the DOS executable `HARVEST.EXE` in our `harvester-demo` Ghidra project, analyzed with Ghidra 12.1.2. The names are analyst-applied. The executable is not distributed with this article.

## The mystery: where did the dialogue code go?

We were comparing two analyses of *Harvester*. One project had named dialogue handlers such as `handle_talk_to_herrill`; the other, `harvester-demo`, appeared to have almost none of them.

The game plainly knew how to talk to Herrill. The executable contained strings such as `HERRILL`, `HERRILL_LOG`, and dozens of dialogue response identifiers. Yet Ghidra's Function window did not contain a function at the address where the game dispatched Herrill's dialogue.

This was not missing code. It was missing *structure*.

Ghidra's normal recursive disassembly starts from known entry points and follows direct control flow. A function reached only through an indirect call can remain invisible until something tells Ghidra that a data value is a code pointer. The clue in this executable was a regular series of names followed by addresses.

**[IMAGE 1: Hero image - split Ghidra view showing the raw dispatch table on the left and the recovered `handle_talk_to_herrill` decompilation on the right]**

*Screenshot instructions: in the Listing, press `G`, enter `000c2d54`, and show about six records. Open a second CodeBrowser window at `0002dc00`, with the Decompiler visible and `handle_talk_to_herrill` selected. Keep addresses, bytes, labels, and the Decompiler title visible.*

## Finding the table hiding in plain sight

At `0x000c2d54`, the bytes begin like this:

```text
000c2d54  41 55 54 48 4f 52 49 54 59 00 ... 00  AUTHORITY
000c2d74  30 b7 02 00                          0x0002b730
000c2d78  41 55 54 48 4f 52 49 54 59 32 ... 00  AUTHORITY2
000c2d98  30 b7 02 00                          0x0002b730
000c2d9c  42 45 47 47 41 52 00 ... 00           BEGGAR
000c2dbc  40 4e 03 00                          0x00034e40
```

Three properties make this look like a dispatch table rather than unrelated strings:

1. The records repeat at a fixed stride of `0x24` bytes.
2. Every record contains a 32-byte, NUL-padded name followed by a 4-byte little-endian value.
3. Those values land in the program's code region, often at plausible function prologues or at code with many inbound references.

The natural C representation is:

```c
typedef void (*TalkHandler)(void); // Provisional until the calling convention is known.

typedef struct TalkDispatchEntry {
    char name[32];
    TalkHandler handler;
} TalkDispatchEntry;

TalkDispatchEntry talk_dispatch[64];
```

The complete table occupies 64 records, or 2,304 bytes. It contains 47 unique code pointers because several scene-specific names share a handler:

```text
index  record      name              handler
-----  ----------  ----------------  ----------
0      0x000c2d54  AUTHORITY         0x0002b730
1      0x000c2d78  AUTHORITY2        0x0002b730
12     0x000c2f04  DWAYNE            0x0003a3f0
13     0x000c2f28  DWAYNE_DNALFT     0x0003a3f0
14     0x000c2f4c  DWAYNE_ST_BEDRM   0x0003a3f0
20     0x000c3024  HERRILL           0x0002dc00
21     0x000c3048  HERRILL_LOG       0x0002dc00
35     0x000c3240  MOM               0x00031140
60     0x000c35c4  STEPHANIE         0x00036810
63     0x000c3630  WASP_WOMAN        0x0002fde0
```

That duplication is useful evidence. It says the first field is a lookup key or scene identity and the second field is behavior. It also warns us not to create 64 functions: there are only 47 unique targets.

**[CHART 1: 64 dispatch records -> 47 unique handler pointers -> 48 known talk handlers after adding Whaley, which is referenced outside this table]**

*Chart instructions: use a three-stage funnel or Sankey. Label the stages exactly as above. Add a note that aliases such as `HERRILL_LOG` converge on the same implementation.*

## Turn bytes into a data structure first

The most valuable manual operation is not "create function." It is teaching Ghidra what the table means.

### Build the types

1. Open **Window -> Data Type Manager**.
2. Create a function definition named `TalkHandler`. Start with `void TalkHandler(void)`; this is deliberately conservative.
3. Create a structure named `TalkDispatchEntry`.
4. Add `char[32] name` at offset `0x00`.
5. Add a 32-bit pointer to `TalkHandler` named `handler` at offset `0x20`.
6. Confirm that the structure length is `0x24`.

Ghidra has a dedicated `FunctionDefinitionDataType` specifically for uses such as function pointers, so this is more expressive than applying an untyped `pointer32`. A typed pointer also gives the decompiler a prototype it can propagate through indirect calls. See Ghidra's official [`FunctionDefinitionDataType` API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/FunctionDefinitionDataType.html) and [`Pointer` API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/Pointer.html).

### Apply the table

1. Press `G` and go to `000c2d54`.
2. Clear conflicting data definitions if necessary; do not clear instructions outside the table range.
3. Apply `TalkDispatchEntry` at the first record.
4. Create an array of 64 elements.
5. Rename the array `talk_dispatch`.

The Listing changes from an undifferentiated run of strings and DWORDs into named fields. Each `handler` value becomes a navigable reference. Double-clicking `HERRILL.handler` now takes us to `0x0002dc00`.

**[IMAGE 2: Before/after Listing view of `0x000c2d54`]**

*Screenshot instructions: capture the same address and number of rows twice. Before applying the type, show strings interleaved with undefined DWORD bytes. Afterward, expand the `TalkDispatchEntry[64]` array and show the `name` and typed `handler` fields. Keep the Data Type column visible.*

### Create functions without a custom script

For a small table, the Ghidra-only workflow is enough:

1. Follow a `handler` pointer to its target.
2. Use **Code -> Disassemble** if the target is still undefined.
3. Use **Create Function** at the exact target address.
4. Give it a provisional name such as `handle_talk_to_herrill`.
5. Repeat for unique pointer values only.

Ghidra computes a function body by following non-call flows from the entry. The underlying command is documented in [`CreateFunctionCmd`](https://ghidra.re/ghidra_docs/api/ghidra/app/cmd/function/CreateFunctionCmd.html). Creating the function is not cosmetic: it creates an ownership boundary for instructions, enables function graphs and callers/callees, gives the decompiler an entry point, and lets later analyzers operate on the recovered body.

For 47 targets, repetition becomes both tedious and error-prone. That is where a small script is justified.

## A Ghidra-only table seeding script

The following script is enough to reproduce the first important recovery step. It reads the 64 records, deduplicates their pointers, disassembles each target, and creates a provisionally named function.

Run it from Ghidra's **Window -> Script Manager** against a fresh import *before* the main auto-analysis pass. Ghidra's official [`GhidraScript` documentation](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html) describes the `currentProgram` context and the Java script model.

```java
// Seed functions referenced by Harvester's talk dispatch table.
// @category Harvester

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;

import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

public class SeedTalkDispatchTable extends GhidraScript {
    private static final long TABLE = 0x000c2d54L;
    private static final int RECORDS = 64;
    private static final int NAME_SIZE = 32;
    private static final int RECORD_SIZE = 0x24;

    @Override
    public void run() throws Exception {
        Set<Long> seen = new HashSet<>();

        for (int i = 0; i < RECORDS && !monitor.isCancelled(); i++) {
            Address record = toAddr(TABLE + (long) i * RECORD_SIZE);
            byte[] rawName = new byte[NAME_SIZE];
            currentProgram.getMemory().getBytes(record, rawName);
            String key = decodeName(rawName);

            Address pointerField = record.add(NAME_SIZE);
            long targetOffset = Integer.toUnsignedLong(
                currentProgram.getMemory().getInt(pointerField));
            if (!seen.add(targetOffset)) {
                continue;
            }

            Address entry = toAddr(targetOffset);
            if (getInstructionAt(entry) == null && !disassemble(entry)) {
                printerr("Could not disassemble " + key + " at " + entry);
                continue;
            }

            Function function = getFunctionAt(entry);
            if (function == null) {
                function = createFunction(entry, null);
            }
            if (function == null) {
                printerr("Could not create function for " + key + " at " + entry);
                continue;
            }

            String name = "handle_talk_to_" + key.toLowerCase(Locale.ROOT);
            function.setName(name, SourceType.USER_DEFINED);
            println(name + " @ " + entry);
        }
    }

    private String decodeName(byte[] bytes) {
        int length = 0;
        while (length < bytes.length && bytes[length] != 0) {
            length++;
        }
        return new String(bytes, 0, length, StandardCharsets.US_ASCII)
            .replaceAll("[^A-Za-z0-9_]+", "_");
    }
}
```

The table provides strong evidence for *where functions start*. It does not prove their names, signatures, or semantics. Treat generated names as a work queue, then confirm each function through strings, callers, state access, and comparison with related binaries.

There is also one cleanup caveat: if a previous analysis already created an interior function, `createFunction()` can reject the correct outer body because function bodies may not overlap. Fix the stale fragment first or begin from a fresh import.

## The second bug: a call that appeared to end the function

Surfacing the correct entry points exposed a different failure. Ghidra sometimes stopped a handler immediately after a call to `play_dialogue_line`.

The machine code around Herrill made the problem visible:

```asm
0002e232  XOR  EBX,EBX
0002e234  CALL 0x0007a460        ; play_dialogue_line
0002e239  MOV  EDX,0x000b4a6d
0002e23e  MOV  EAX,0x00002f6e
0002e243  XOR  EBX,EBX
0002e245  CALL 0x0007a460        ; play_dialogue_line
0002e24a  MOV  EAX,0x00000281    ; valid continuation
0002e24f  CALL 0x0003a280        ; load_dialogue_response_line
0002e254  MOV  ESI,EAX
```

Before repair, Ghidra treated the call at `0x0002e245` as terminating. The valid instruction at `0x0002e24a` was not part of the preceding flow. A later heuristic pass found those bytes independently and created an interior fragment there.

Conceptually, the broken Listing looked like this:

```asm
; ... body discovered from some earlier seed ...
0002e245  CALL play_dialogue_line
          ; no fall-through edge; function body stops

FUN_0002e24a:
0002e24a  MOV  EAX,0x281         ; suspicious: no prologue, starts after a call
0002e24f  CALL load_dialogue_response_line
; ... fragment continues to 0x0002e987 ...
```

This is not a real `return`. There is no `RET` after `0x0002e245`, no epilogue restoring registers, and no jump to a shared epilogue. It is an *analysis-level* termination: the callee was marked non-returning, or the call instruction had a `CALL_RETURN` flow override, so Ghidra removed the fall-through edge.

That distinction is one of the most useful diagnostics in recursive disassembly:

| Real early return | Suspicious analysis termination |
| --- | --- |
| A `RET`, tail jump, or branch to an epilogue exists | A normal `CALL` is the final owned instruction |
| Stack/register cleanup is coherent | Valid-looking bytes immediately follow the call |
| Other callers agree that the callee does not return | Other call sites clearly continue after the same callee |
| Function entry is supported by calls or a table | A new fragment begins mid-sequence, often without a prologue |

The decompiler reflected the same damaged graph. To verify the symptom without modifying the repaired database, we temporarily marked `play_dialogue_line` as non-returning inside a rolled-back Ghidra transaction and decompiled Herrill. This is the actual output shape:

```c
// Before: Ghidra removes everything reachable only after this call.
if (g_herrill_talk_state_block == 0) {
            /* WARNING: Subroutine does not return */
    play_dialogue_line(unaff_EBP, unaff_EDI, unaff_ESI);
}
g_herrill_talk_state_block = DAT_000d6578;
            /* WARNING: Subroutine does not return */
play_dialogue_line(unaff_EBP, unaff_EDI, unaff_ESI);
```

After restoring the fall-through, code on both sides became one function:

```c
// After: the next dialogue response is visibly part of the same handler.
play_dialogue_line(unaff_EBP, unaff_EDI, unaff_ESI);
pcVar5 = load_dialogue_response_line(0x281);
do {
    cVar1 = *pcVar5;
    *pcVar4 = cVar1;
    if (cVar1 == '\0') break;
    cVar1 = pcVar5[1];
    pcVar5 += 2;
    pcVar4[1] = cVar1;
    pcVar4 += 2;
} while (cVar1 != '\0');
```

The repaired `handle_talk_to_herrill` starts at the table target `0x0002dc00`, owns the former fragment at `0x0002e24a`, and continues through `0x0002e987`. Ghidra now reports 943 instructions in the handler, including 76 direct calls to `play_dialogue_line`.

**[IMAGE 3: Before/after Function Graph at the call ending at `0x0002e245`]**

*Screenshot instructions: make the "before" image in a disposable copy of the program. Mark `play_dialogue_line` at `0x0007a460` as **No Return**, enable flow repair, and reanalyze the affected region. Center the graph on the block ending at `0x0002e245`. For "after," use the repaired project and center on the same address; show the outgoing edge to the block beginning at `0x0002e24a`. Never perform this reproduction in the working project.*

**[IMAGE 4: Side-by-side Decompiler output before and after fall-through repair]**

*Screenshot instructions: keep the call at the bottom of the before pane and `load_dialogue_response_line(0x281)` visible in the after pane. Enable line numbers and include the function name/address in each title bar. Add a small annotation: "No RET in the bytes."*

## What actually repaired the project

We used Codex with two Ghidra MCP instances: the named reference project on port 8089 and `harvester-demo` on port 8090. Codex compared the projects, decoded the dispatch table, and generated `RepairDemoTalkHandlers.java`. The script was not required to *understand* the bug; it made the repair repeatable and auditable.

We ran five stages in order:

1. Disassemble all 47 unique table targets plus the separately referenced Whaley handler.
2. Mark `play_dialogue_line` as returning, clear stale flow overrides, and disassemble each missing post-call instruction.
3. Create functions at the true entries.
4. Remove the stale Herrill fragment at `0x0002e24a` and recreate the body from `0x0002dc00`.
5. Transfer high-confidence names and documentation, then verify every body.

The essential repair loop was small:

```java
Function play = getFunctionAt(toAddr(0x0007a460L));
play.setNoReturn(false);

for (Instruction instruction : dialogueCalls) {
    if (instruction.getFlowOverride() != FlowOverride.NONE) {
        instruction.setFlowOverride(FlowOverride.NONE);
    }

    Address next = instruction.getAddress().add(instruction.getLength());
    if (getInstructionAt(next) == null) {
        disassemble(next);
    }
}

removeFunction(getFunctionAt(toAddr(0x0002e24aL)));
createFunction(toAddr(0x0002dc00L), "handle_talk_to_herrill");
```

The full local script, `~/ghidra_scripts/RepairDemoTalkHandlers.java`, adds transactions, multiple repair passes, overlap checks, naming, and verification. Its final check reported:

```text
expected=48
present=48
missing=0
dialogueCalls=2239
gaps=0
functionAtHerrillFragment=null
containingHerrillFragment=handle_talk_to_herrill @ 0002dc00
```

Those assertions matter more than a clean-looking Decompiler window. A repair is complete only when every table target owns a function, each returning dialogue call has a real fall-through instruction in the same handler, and no stale interior function overlaps the intended body.

### Asking Codex to generate the repair

The useful prompt was evidence-oriented rather than "make Ghidra better":

```text
In HARVEST.EXE, inspect the 64 records at 0x000c2d54. Treat each record as
char name[32] followed by a 32-bit little-endian code pointer. Deduplicate the
targets, verify each target's first instructions, and generate a transactional
Ghidra Java script that:

1. disassembles every unique target,
2. creates a function at each exact target,
3. treats play_dialogue_line at 0x0007a460 as returning,
4. clears erroneous call flow overrides and disassembles the fall-through,
5. rejects or removes overlapping interior fragments only when the table and
   control flow prove the outer entry, and
6. verifies target count, call fall-through, and function ownership.

Print every mutation and a final machine-readable summary. Do not infer names
beyond the table keys without corroborating evidence.
```

With Ghidra MCP, we executed the generated Java source through `run_script_inline`, passing `step2`, `step3`, `step4`, `step5`, and finally `verify`. Without MCP, place the script in `~/ghidra_scripts`, refresh Script Manager, and expose each stage as a separate script entry point or replace the argument dispatch with the single stage you intend to run. The analysis and repair APIs are standard Ghidra APIs; MCP was only the transport.

## Configure the first analysis pass to avoid the damage

Can this be solved entirely through configuration? Partly.

Correct analyzer settings can prevent the false non-return damage. They cannot always discover an application-specific table whose records mix text and pointers. The deterministic solution is therefore:

1. seed or type the dispatch table before full analysis;
2. use conservative flow analyzers for the first pass;
3. run speculative analyzers later, after known callees and function boundaries exist.

Ghidra's own training material recommends a layered approach: recover function starts and data first, then run more speculative analysis. It also explicitly calls out non-return damage and scripts for repairing it. See [Introduction to Ghidra](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html) and [Improving Disassembly and Decompilation](https://ghidra.re/ghidra_docs/GhidraClass/Advanced/improvingDisassemblyAndDecompilation.pdf).

### Recommended GUI settings for this executable

On a fresh import, decline or cancel the automatic analysis prompt long enough to apply the table type or run `SeedTalkDispatchTable.java`. Then open **Analysis -> Auto Analyze** and use this first-pass profile:

| Analyzer or option | First pass | Reason |
| --- | --- | --- |
| Disassemble Entry Points | On | Establish loader-provided roots. |
| Reference | On | Recover scalar and pointer references. |
| Reference -> References to Pointers | On | Preserve pointer relationships. |
| Reference -> Subroutine References | On | Treat code destinations as possible subroutines. |
| Data Reference | On | Analyze references produced by typed table data. |
| Data Reference -> References to Pointers | On | Follow the newly typed handler field. |
| Data Reference -> Subroutine References | On | Feed handler destinations into function recovery. |
| Create Address Tables | On | Recover other regular address arrays. |
| Function Start Pre Search / Search / After Code / After Data | On | Recover conventional function starts around known code. |
| Aggressive Instruction Finder | Off | Avoid promoting interior byte sequences before roots are trustworthy. |
| Non-Returning Functions - Discovered | **Off** | Prevent a false no-return classification from deleting valid fall-through. |
| Non-Returning Functions - Discovered -> Repair Flow Damage | **Off** | Do not let a speculative classification clear downstream code. |

These are the settings currently saved in `harvester-demo`. If the program's code lives in a memory block that Ghidra marked as data or non-executable, consider enabling **Function Start Search -> Search Data Blocks** for a later targeted pass. It is intentionally not the default here because scanning arbitrary data for prologues can manufacture interior fragments.

After the table targets and common callees are stable, you may re-enable **Non-Returning Functions - Discovered** with a high evidence threshold. In our investigation, we used a function non-return threshold of 100. Review every proposed non-returning function before enabling **Repair Flow Damage**. Functions such as `exit` truly do not return; dialogue renderers usually do.

The official advanced course notes that the discovered non-return analyzer's evidence threshold is configurable and that incorrect no-return decisions require flow repair. Ghidra's [`AnalysisPriority` API](https://ghidra.re/ghidra_docs/api/ghidra/app/services/AnalysisPriority.html) explains why bad flow must be corrected before function and switch recovery: later analysis is built on those early edges.

### Make it deterministic with a pre-analysis script

For repeatable imports, run the table seeder as a headless pre-script:

```bash
analyzeHeadless "$HOME/ghidra-projects" harvester-demo \
  -import /path/to/HARVEST.EXE \
  -scriptPath "$HOME/ghidra_scripts" \
  -preScript SeedTalkDispatchTable.java \
  -postScript VerifyTalkHandlers.java
```

Ghidra defines pre-scripts as running after import and before auto-analysis; post-scripts run afterward. That ordering is documented by the official [`HeadlessOptions`](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessOptions.html) and [`HeadlessAnalyzer`](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessAnalyzer.html) APIs.

A robust pre-script should also set the intended analysis options programmatically, or the project should use a saved analysis profile. Do not assume another analyst's GUI defaults match yours.

## A practical checklist for the next unknown executable

When you suspect a function-pointer table:

- Look for fixed-stride records containing addresses into executable memory.
- Check whether several semantic keys share one target; aliases strengthen the dispatch-table hypothesis.
- Verify target alignment, prologues, inbound references, strings, and eventual returns.
- Apply a structure and a function-definition pointer, not just a sequence of DWORDs.
- Create functions at the pointer values, never at the table slots themselves.
- Deduplicate targets before naming.
- Treat names and prototypes as provisional until callers corroborate them.

When a function appears to terminate too early:

- Inspect the final instruction. Is it really `RET` or merely `CALL`?
- Check the callee's **No Return** property.
- Inspect the call's flow override and fall-through edge.
- Disassemble the bytes immediately after the call and test whether they form coherent code.
- Look for an interior `FUN_*` beginning immediately after the call.
- Compare other call sites to the same callee.
- Recreate the function body only after correcting the callee and instruction flow.

## The epiphany

The breakthrough was not a better decompiler expression or a clever rename. It was recognizing that code discovery and data typing are the same problem viewed from opposite directions.

Before typing the table, `0x0002dc00` was merely a number stored after `HERRILL`. After typing it as a function pointer, it became a navigable relationship: a data record selected behavior. After fixing the false non-return edge, `0x0002e24a` stopped looking like a new function and became what the bytes had said all along: the next instruction in Herrill's conversation.

That is where Ghidra is especially effective. Structures make repeated binary layouts legible. Typed pointers turn values into references. Functions give instructions ownership. The Function Graph makes missing edges visible. The Decompiler then converts the recovered graph into something an analyst can reason about.

The decompiler did not discover the truth by itself. We gave Ghidra the right roots and the right flow, and the rest of the program became easier to see.

**[CHART 2: Before/after analysis outcome]**

*Chart instructions: use two columns. Before: `64 records`, `47 unique pointers`, `0 functions at table targets`, `1 Herrill interior fragment`. After: `48 known talk handlers`, `2,239 verified dialogue calls`, `0 flow gaps`, `0 stale Herrill fragment`. Include body range `0x0002dc00..0x0002e987` under the after column.*

## References

- [Introduction to Ghidra - official course material](https://ghidra.re/ghidra_docs/GhidraClass/Beginner/Introduction_to_Ghidra_Student_Guide.html)
- [Improving Disassembly and Decompilation - official advanced course](https://ghidra.re/ghidra_docs/GhidraClass/Advanced/improvingDisassemblyAndDecompilation.pdf)
- [`GhidraScript` API](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html)
- [`CreateFunctionCmd` API](https://ghidra.re/ghidra_docs/api/ghidra/app/cmd/function/CreateFunctionCmd.html)
- [`FunctionDefinitionDataType` API](https://ghidra.re/ghidra_docs/api/ghidra/program/model/data/FunctionDefinitionDataType.html)
- [`HeadlessOptions` API](https://ghidra.re/ghidra_docs/api/ghidra/app/util/headless/HeadlessOptions.html)
- [`AnalysisPriority` API](https://ghidra.re/ghidra_docs/api/ghidra/app/services/AnalysisPriority.html)
