import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
public class CampaignEvidence extends GhidraScript {
 public void run()throws Exception{
  var config=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();
  var result=new JsonObject();var rows=new JsonArray();var d=new DecompInterface();try{
   var opts=new DecompileOptions();opts.grabFromProgram(currentProgram);d.setOptions(opts);if(!d.openProgram(currentProgram))throw new Exception(d.getLastMessage());
   for(var e:config.getAsJsonArray("addresses")){monitor.checkCancelled();var address=toAddr(e.getAsString());var f=getFunctionAt(address);if(f==null)throw new Exception("Missing function "+address);
    var r=d.decompileFunction(f,30,monitor);if(!r.decompileCompleted())throw new Exception("Decompile "+address+": "+r.getErrorMessage());var row=new JsonObject();row.addProperty("address",address.toString());row.addProperty("decompilation",r.getDecompiledFunction().getC());var ins=new JsonArray();var iter=currentProgram.getListing().getInstructions(f.getBody(),true);while(iter.hasNext()){var i=iter.next();var q=new JsonObject();q.addProperty("address",i.getAddress().toString());q.addProperty("text",i.toString());q.addProperty("bytes",HexFormat.of().formatHex(i.getBytes()));q.addProperty("raw_pcode",Arrays.toString(i.getPcode(false)));q.addProperty("pcode",Arrays.toString(i.getPcode(true)));ins.add(q);}row.add("instructions",ins);var tables=new JsonArray();for(var table:r.getHighFunction().getJumpTables()){var t=new JsonObject();t.addProperty("address",table.getSwitchAddress().toString());var targets=new JsonArray();for(var a:table.getCases())targets.add(a.toString());t.add("targets",targets);tables.add(t);}row.add("jump_tables",tables);
    var callers=new JsonArray();for(var c:f.getCallingFunctions(monitor))callers.add(c.getEntryPoint().toString());row.add("callers",callers);rows.add(row);
   }
  }finally{d.dispose();}result.add("functions",rows);result.addProperty("complete",true);java.nio.file.Files.writeString(java.nio.file.Path.of(config.get("output").getAsString()),result.toString());println("CAMPAIGN_RESULT:complete");
 }
}
