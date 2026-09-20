import ghidra.app.script.GhidraScript;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import com.google.gson.*;

/** Isolated creation tests; separate script phases expose real rollback boundaries. */
public class CampaignCreationFixture extends GhidraScript {
    void invoke(String script, JsonObject args) throws Exception {
        args.addProperty("script_directory", getSourceFile().getParentFile().getAbsolutePath());
        var file = new generic.jar.ResourceFile(getSourceFile().getParentFile(), script);
        var instance = ghidra.app.script.GhidraScriptUtil.getProvider(file)
            .getScriptInstance(file, new java.io.PrintWriter(System.err, true));
        instance.setScriptArgs(new String[] {Base64.getEncoder().encodeToString(
            args.toString().getBytes(StandardCharsets.UTF_8))});
        instance.execute(state, monitor, new java.io.PrintWriter(System.out, true));
    }

    JsonObject capture(Path path) throws Exception {
        var args = new JsonObject(); args.addProperty("output", path.toString());
        invoke("CampaignInventory.java", args);
        return JsonParser.parseString(Files.readString(path)).getAsJsonObject();
    }

    public void run() throws Exception {
        var root = Path.of(getScriptArgs()[0]).resolve("creation");
        Files.createDirectories(root);
        String phase = getScriptArgs()[1];
        if (phase.equals("prepare")) {
            analyzeChanges(currentProgram);
            if (getFunctionContaining(toAddr(0x1005)) != null)
                throw new Exception("Fixture requires decoded unowned bytes");
            var before = capture(root.resolve("before.json"));
            var digest = java.security.MessageDigest.getInstance("SHA-256");
            for (long offset : new long[] {0x1005, 0x1007}) {
                var i = getInstructionAt(toAddr(offset));
                digest.update(i.getAddress().toString().getBytes(StandardCharsets.UTF_8));
                digest.update(i.getBytes());
            }
            var change = new JsonObject(); change.addProperty("kind", "create_function");
            change.addProperty("address", toAddr(0x1005).toString());
            var ranges = new JsonArray(); var pair = new JsonArray();
            pair.add(toAddr(0x1005).toString()); pair.add(toAddr(0x1007).toString()); ranges.add(pair);
            change.add("ranges", ranges);
            change.addProperty("instruction_hash", HexFormat.of().formatHex(digest.digest()));
            var changes = new JsonArray(); changes.add(change);
            var plan = new JsonObject(); plan.addProperty("id", "fixture-creation");
            plan.add("identity", before.get("identity")); plan.add("changes", changes);
            var args = new JsonObject(); args.add("plan", plan); args.addProperty("mode", "trial");
            args.addProperty("directory", root.toString()); args.addProperty("output", root.resolve("result.json").toString());
            Files.writeString(root.resolve("args.json"), args.toString());
            return;
        }
        var args = JsonParser.parseString(Files.readString(root.resolve("args.json"))).getAsJsonObject();
        if (phase.equals("failure")) {
            // First operation succeeds, second overlaps it; the entire batch must roll back.
            var changes = args.getAsJsonObject("plan").getAsJsonArray("changes");
            changes.add(changes.get(0).deepCopy());
            invoke("CampaignRepair.java", args);
            throw new Exception("Overlapping creation accepted");
        }
        if (phase.equals("trial")) {
            if (!capture(root.resolve("rolled-back.json")).equals(
                    JsonParser.parseString(Files.readString(root.resolve("before.json")))))
                throw new Exception("Creation failure did not roll back after script boundary");
            // Each invalid first operation must fail before creating a function.
            for (String test : new String[] {"hash", "middle", "truncated", "undefined", "owned"}) {
                var invalid = args.deepCopy();
                var c = invalid.getAsJsonObject("plan").getAsJsonArray("changes").get(0).getAsJsonObject();
                var pair = c.getAsJsonArray("ranges").get(0).getAsJsonArray();
                if (test.equals("hash")) c.addProperty("instruction_hash", "0".repeat(64));
                if (test.equals("middle")) {c.addProperty("address", toAddr(0x1006).toString()); pair.set(0, new JsonPrimitive(toAddr(0x1006).toString()));}
                if (test.equals("truncated")) pair.set(1, new JsonPrimitive(toAddr(0x1005).toString()));
                if (test.equals("undefined")) pair.set(1, new JsonPrimitive(toAddr(0x1008).toString()));
                if (test.equals("owned")) {c.addProperty("address", toAddr(0x1004).toString()); pair.set(0, new JsonPrimitive(toAddr(0x1004).toString()));}
                boolean failed = false;
                try {invoke("CampaignRepair.java", invalid);} catch (Exception expected) {failed = true;}
                if (!failed || getFunctionAt(toAddr(0x1005)) != null)
                    throw new Exception("Invalid creation accepted: " + test);
            }
            // Creation must also execute through the refreshed GUI worker bundle.
            var output = Path.of(args.get("output").getAsString());
            Files.deleteIfExists(output);
            javax.swing.SwingUtilities.invokeAndWait(() -> {
                try {invoke("CampaignRepair.java", args);}
                catch (Exception error) {throw new RuntimeException(error);}
            });
            long deadline = System.nanoTime() + 120_000_000_000L;
            while (!Files.exists(output)) {
                if (System.nanoTime() > deadline) throw new Exception("Creation worker timed out");
                Thread.sleep(50);
            }
            var response = JsonParser.parseString(Files.readString(output)).getAsJsonObject();
            if (!response.get("complete").getAsBoolean() || !response.get("rolled_back").getAsBoolean())
                throw new Exception("Creation worker failed: " + response);
            return;
        }
        if (phase.equals("apply")) {
            if (!capture(root.resolve("trial-rollback.json")).equals(
                    JsonParser.parseString(Files.readString(root.resolve("before.json")))))
                throw new Exception("Creation trial did not roll back");
            var nativeFile = root.resolve("trial-native").resolve(toAddr(0x1005) + ".json");
            if (!Files.exists(nativeFile) || JsonParser.parseString(Files.readString(nativeFile))
                    .getAsJsonObject().get("decompilation").getAsString().isBlank())
                throw new Exception("Created function has no native evidence");
            args.addProperty("mode", "apply"); invoke("CampaignRepair.java", args); return;
        }
        if (phase.equals("verify")) {
            analyzeChanges(currentProgram);
            var f = getFunctionAt(toAddr(0x1005));
            if (f == null || !f.getName().equals("FUN_00001005") || f.getBody().getNumAddresses() != 3)
                throw new Exception("Created function did not stay applied");
            capture(root.resolve("after.json"));
            println("CAMPAIGN_CREATION_PASS"); return;
        }
        throw new Exception("Unknown creation fixture phase");
    }
}
