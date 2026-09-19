import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.symbol.*;
import java.nio.file.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
public class CampaignFixture extends GhidraScript {
 void invoke(String script,JsonObject args)throws Exception{
  var file=new generic.jar.ResourceFile(getSourceFile().getParentFile(),script);
  var instance=ghidra.app.script.GhidraScriptUtil.getProvider(file).getScriptInstance(file,new java.io.PrintWriter(System.err,true));
  instance.setScriptArgs(new String[]{Base64.getEncoder().encodeToString(args.toString().getBytes(StandardCharsets.UTF_8))});
  instance.execute(state,monitor,new java.io.PrintWriter(System.out,true));
 }
 public void run()throws Exception{
  var root=Path.of(getScriptArgs()[0]);String phase=getScriptArgs()[1];
  if(phase.equals("prepare")){
   int tx=currentProgram.startTransaction("Fixture initialization");try{for(int n=0;n<2;n++){var a=toAddr(n);disassemble(a);currentProgram.getFunctionManager().createFunction(n==0?"first":"second",a,new AddressSet(a),SourceType.USER_DEFINED);}}finally{currentProgram.endTransaction(tx,true);}
   var args=new JsonObject();args.addProperty("output",root.resolve("inventory.json").toString());invoke("CampaignInventory.java",args);var before=JsonParser.parseString(Files.readString(root.resolve("inventory.json"))).getAsJsonObject();
   var plan=new JsonObject();plan.addProperty("id","fixture-transaction");plan.add("identity",before.get("identity"));var changes=new JsonArray();
   for(int n=0;n<2;n++){var c=new JsonObject();c.addProperty("kind","function");c.addProperty("address",toAddr(n).toString());c.addProperty("old_name",n==0?"first":"second");c.addProperty("new_name",n==0?"renamed_first":"invalid name");changes.add(c);}plan.add("changes",changes);args.add("plan",plan);args.add("before",before);args.addProperty("output",root.resolve("rename.json").toString());Files.writeString(root.resolve("fixture-args.json"),args.toString());return;
  }
  var args=JsonParser.parseString(Files.readString(root.resolve("fixture-args.json"))).getAsJsonObject();
  if(phase.equals("abi")){
   var changes=new JsonArray();var model=new JsonObject();model.addProperty("kind","compiler_model");model.addProperty("name","__fixture_register");model.addProperty("xml","<prototype name=\"__fixture_register\" extrapop=\"4\" stackshift=\"4\"><input><pentry minsize=\"4\" maxsize=\"4\"><register name=\"EAX\"/></pentry></input><output><pentry minsize=\"4\" maxsize=\"4\"><register name=\"EAX\"/></pentry></output><unaffected><register name=\"EBX\"/><register name=\"ESI\"/><register name=\"EDI\"/><register name=\"EBP\"/></unaffected></prototype>");changes.add(model);
   var contract=JsonParser.parseString("{\"kind\":\"abi\",\"convention\":\"__fixture_register\",\"return\":{\"type\":\"/uint\",\"storage\":{\"register\":\"EAX\"}},\"parameters\":[{\"name\":\"value\",\"type\":\"/uint\",\"storage\":{\"register\":\"EAX\"}}],\"varargs\":false,\"noreturn\":false}").getAsJsonObject();contract.addProperty("address",toAddr(0).toString());changes.add(contract);args.getAsJsonObject("plan").addProperty("id","fixture-abi");args.getAsJsonObject("plan").add("changes",changes);invoke("CampaignTypes.java",args);
   var f=getFunctionAt(toAddr(0));if(f.getParameterCount()!=1||!f.getParameter(0).getRegister().getName().equals("EAX")||!f.getCallingConventionName().equals("__fixture_register"))throw new Exception("ABI readback failed");println("CAMPAIGN_ABI_PASS");return;
  }
  if(phase.startsWith("layout")){
   if(phase.equals("layout-verify")&&currentProgram.getDataTypeManager().getDataType("/Fixture/Rejected")!=null)throw new Exception("Layout rollback failed");
   var changes=JsonParser.parseString("[{\"kind\":\"structure\",\"path\":\"/Fixture/Header\",\"length\":4,\"fields\":[{\"offset\":0,\"length\":4,\"type\":\"/uint\",\"name\":\"size\"}]}]").getAsJsonArray();
   if(phase.equals("layout-failure")){changes.get(0).getAsJsonObject().addProperty("path","/Fixture/Rejected");var c=new JsonObject();c.addProperty("kind","data_type");c.addProperty("address",toAddr(0).toString());c.addProperty("type","/Fixture/Rejected");c.addProperty("length",4);changes.add(c);}
   args.getAsJsonObject("plan").addProperty("id",phase);args.getAsJsonObject("plan").add("changes",changes);invoke("CampaignTypes.java",args);
   if(phase.equals("layout-failure"))throw new Exception("Code overlap accepted");
   var type=currentProgram.getDataTypeManager().getDataType("/Fixture/Header");if(type==null||type.getLength()!=4)throw new Exception("Layout creation failed");println("CAMPAIGN_LAYOUT_PASS");return;
  }

  if(phase.equals("failure")){invoke("CampaignRename.java",args);throw new Exception("Expected invalid-name failure did not occur");}
  if(!getFunctionAt(toAddr(0)).getName().equals("first")||!getFunctionAt(toAddr(1)).getName().equals("second"))throw new Exception("Mid-batch rollback failed after script boundary");
  args.getAsJsonObject("plan").getAsJsonArray("changes").get(1).getAsJsonObject().addProperty("new_name","renamed_second");invoke("CampaignRename.java",args);
  if(!getFunctionAt(toAddr(0)).getName().equals("renamed_first")||!getFunctionAt(toAddr(1)).getName().equals("renamed_second"))throw new Exception("Successful rename failed");
  invoke("CampaignRename.java",args);args=new JsonObject();args.addProperty("output",root.resolve("evidence.json").toString());var addresses=new JsonArray();addresses.add(toAddr(0).toString());args.add("addresses",addresses);invoke("CampaignEvidence.java",args);println("CAMPAIGN_FIXTURE_PASS");
 }
}
