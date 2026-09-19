import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.google.gson.*;

/** Declarative metadata changes. This runner never writes executable bytes. */
public class CampaignRepair extends GhidraScript {
    void invoke(String script, JsonObject args) throws Exception {
        var file = new generic.jar.ResourceFile(getSourceFile().getParentFile(), script);
        var instance = ghidra.app.script.GhidraScriptUtil.getProvider(file)
            .getScriptInstance(file, new java.io.PrintWriter(System.err, true));
        instance.setScriptArgs(new String[] { Base64.getEncoder().encodeToString(
            args.toString().getBytes(StandardCharsets.UTF_8)) });
        instance.execute(state, monitor, new java.io.PrintWriter(System.out, true));
    }

    Instruction instruction(JsonObject change) throws Exception {
        var i = getInstructionAt(toAddr(change.get("address").getAsString()));
        if (i == null || !HexFormat.of().formatHex(i.getBytes()).equals(change.get("bytes").getAsString()))
            throw new Exception("Instruction bytes differ from proposal");
        return i;
    }

    void change(JsonObject c) throws Exception {
        String kind = c.get("kind").getAsString();
        if (kind.equals("analyzer_option")) {
            var options = currentProgram.getOptions("Analysis");
            String key = c.get("address").getAsString();
            if (!key.equals("Shared Return Calls.Assume Contiguous Functions Only") ||
                !options.contains(key) || options.getBoolean(key, false) != c.get("old_value").getAsBoolean())
                throw new Exception("Missing or stale analyzer option");
            options.setBoolean(key, c.get("value").getAsBoolean());
        } else if (kind.equals("body") || kind.equals("remove_function")) {
            var f = getFunctionAt(toAddr(c.get("address").getAsString()));
            if (f == null || !f.getBody().toString().equals(c.get("old_body").getAsString()))
                throw new Exception("Stale function ownership");
            if (kind.equals("remove_function")) {
                if (!f.getName().equals(c.get("old_name").getAsString())) throw new Exception("Stale function name");
                currentProgram.getFunctionManager().removeFunction(f.getEntryPoint());
                return;
            }
            var body = new AddressSet();
            for (var pair : c.getAsJsonArray("ranges")) {
                var r = pair.getAsJsonArray();
                var start = toAddr(r.get(0).getAsString());
                var end = toAddr(r.get(1).getAsString());
                if (start.compareTo(end) > 0) throw new Exception("Reversed body extent");
                for (var at = start; at.compareTo(end) <= 0;) {
                    var i = getInstructionAt(at);
                    if (i == null || i.getMaxAddress().compareTo(end) > 0) throw new Exception("Body must cover whole instructions");
                    var owner = getFunctionContaining(at);
                    if (owner != null && !owner.equals(f)) throw new Exception("Body overlaps another function");
                    at = i.getMaxAddress().add(1);
                }
                body.add(start, end);
            }
            if (!body.contains(f.getEntryPoint())) throw new Exception("Body excludes entrypoint");
            f.setBody(body);
        } else if (kind.equals("flow_override")) {
            var i = instruction(c);
            if (!i.getFlowOverride().toString().equals(c.get("old_override").getAsString()))
                throw new Exception("Stale flow override");
            var override = FlowOverride.valueOf(c.get("override").getAsString());
            if (override != FlowOverride.NONE && override != FlowOverride.BRANCH) throw new Exception("Unsupported flow override");
            if (!i.getFlowType().isFlow()) throw new Exception("Instruction is not control flow");
            var raw = i.getPcode(false);
            i.setFlowOverride(override);
            if (!Arrays.toString(raw).equals(Arrays.toString(i.getPcode(false))))
                throw new Exception("Raw instruction semantics changed");
            // RET-to-branch must keep its stack load and stack adjustment.
            if (Arrays.stream(raw).anyMatch(op -> op.getOpcode() == PcodeOp.RETURN) && override == FlowOverride.BRANCH) {
                var modified = i.getPcode(true);
                for (var op : raw) if (op.getOpcode() == PcodeOp.LOAD || op.getOpcode() == PcodeOp.INT_ADD)
                    if (Arrays.stream(modified).noneMatch(other -> other.toString().equals(op.toString())))
                        throw new Exception("Synthetic return lost stack semantics");
            }
        } else if (kind.equals("jump_table")) {
            var i = instruction(c);
            var f = getFunctionAt(toAddr(c.get("function").getAsString()));
            if (f == null || !f.getBody().contains(i.getAddress()) || !i.getFlowType().isComputed())
                throw new Exception("Computed jump owner is not proven");
            var targets = new ArrayList<Address>();
            for (var item : c.getAsJsonArray("targets")) {
                var target = toAddr(item.getAsString());
                if (getInstructionAt(target) == null || !f.getBody().contains(target))
                    throw new Exception("Jump-table target is outside owner or not an instruction");
                targets.add(target);
            }
            for (var ref : i.getReferencesFrom()) if (ref.getReferenceType().isFlow() && !targets.contains(ref.getToAddress()))
                throw new Exception("Existing flow target conflicts with table");
            for (var target : targets) currentProgram.getReferenceManager().addMemoryReference(
                i.getAddress(), target, RefType.COMPUTED_JUMP, SourceType.USER_DEFINED, -1);
            new JumpTable(i.getAddress(), targets, true, 0).writeOverride(f);
        } else throw new Exception("Unsupported repair kind");
    }

    public void run() throws Exception {
        var config = JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]), StandardCharsets.UTF_8)).getAsJsonObject();
        var plan = config.getAsJsonObject("plan");
        String id = plan.get("id").getAsString();
        var directory = Path.of(config.get("directory").getAsString());
        if (!config.get("mode").getAsString().equals("trial")) throw new Exception("Only rollback trials are supported");
        if (!currentProgram.getExecutableSHA256().equals(plan.getAsJsonObject("identity").get("digest").getAsString()))
            throw new Exception("Executable digest mismatch");
        int tx = currentProgram.startTransaction("Ghidra Manager repair trial " + id);
        boolean succeeded = false;
        try {
            for (var item : plan.getAsJsonArray("changes")) { monitor.checkCancelled(); change(item.getAsJsonObject()); }
            var args = new JsonObject();
            args.addProperty("output", directory.resolve("trial-snapshot.json").toString());
            invoke("CampaignInventory.java", args);
            var addresses = new JsonArray();
            var functions = new ArrayList<Function>();
            var iterator = currentProgram.getFunctionManager().getFunctions(true);
            while (iterator.hasNext()) { var f = iterator.next(); if (!f.isThunk()) functions.add(f); }
            int index = 0;
            var nativeDir = directory.resolve("after-native"); Files.createDirectories(nativeDir);
            try(var previous = Files.newDirectoryStream(nativeDir, "*.json")) { for (var file : previous) Files.delete(file); }
            for (var f : functions) {
                index++;
                addresses.add(f.getEntryPoint().toString());
                if (addresses.size() == 8 || index == functions.size()) {
                    args.add("addresses", addresses);
                    args.addProperty("output", directory.resolve("trial-native.json").toString());
                    invoke("CampaignEvidence.java", args);
                    var nativeResult = JsonParser.parseString(Files.readString(directory.resolve("trial-native.json"))).getAsJsonObject();
                    for (var row : nativeResult.getAsJsonArray("functions")) {
                        String address = row.getAsJsonObject().get("address").getAsString();
                        Files.writeString(nativeDir.resolve(address.replace(':', '_') + ".json"), row.toString());
                    }
                    addresses = new JsonArray();
                }
            }
            succeeded = true;
        } finally {
            currentProgram.endTransaction(tx, false);
            var receipt = new JsonObject(); receipt.addProperty("plan", id); receipt.addProperty("finished", true);
            Files.writeString(directory.resolve("trial-finished.json"), receipt.toString());
        }
        var result = new JsonObject(); result.addProperty("complete", true); result.addProperty("rolled_back", succeeded);
        Files.writeString(Path.of(config.get("output").getAsString()), result.toString());
        println("CAMPAIGN_RESULT:complete");
    }
}
