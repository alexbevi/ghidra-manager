import ghidra.app.script.GhidraScript;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
public class CampaignSaveState extends GhidraScript {
 public void run()throws Exception{
  var config=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();var result=new JsonObject();result.addProperty("complete",true);result.addProperty("changed",currentProgram.isChanged());result.addProperty("program",currentProgram.getDomainFile().getPathname());
  java.nio.file.Files.writeString(java.nio.file.Path.of(config.get("output").getAsString()),result.toString());println("CAMPAIGN_RESULT:complete");
 }
}
