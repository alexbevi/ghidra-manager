import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.data.*;
import java.util.*;
import java.security.MessageDigest;
import com.google.gson.*;

public class CampaignInventory extends GhidraScript {
 String hash(byte[] bytes)throws Exception{return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));}
 public void run()throws Exception{
  var result=new JsonObject();var identity=new JsonObject();var locator=currentProgram.getDomainFile().getProjectLocator();
  identity.addProperty("project",locator.getName());identity.addProperty("project_path",java.nio.file.Path.of(locator.getLocation(),locator.getName()+".gpr").toString());
  identity.addProperty("program_path",currentProgram.getDomainFile().getPathname());identity.addProperty("digest",currentProgram.getExecutableSHA256());
  identity.addProperty("language",currentProgram.getLanguageID().toString());identity.addProperty("compiler",currentProgram.getCompilerSpec().getCompilerSpecID().toString());
  identity.addProperty("image_base",currentProgram.getImageBase().toString());identity.addProperty("format",currentProgram.getExecutableFormat());
  var spaces=new JsonArray();for(var a:currentProgram.getAddressFactory().getAddressSpaces())spaces.add(a.getName());identity.add("address_spaces",spaces);result.add("identity",identity);
  var options=new JsonObject();for(String group:currentProgram.getOptionsNames()){var o=currentProgram.getOptions(group);var v=new JsonObject();for(String name:o.getOptionNames())v.addProperty(name,o.getValueAsString(name));options.add(group,v);}result.add("configuration",options);
  var functions=new JsonArray();var fs=currentProgram.getFunctionManager().getFunctions(true);
  while(fs.hasNext()) {monitor.checkCancelled();var f=fs.next();var row=new JsonObject();row.addProperty("address",f.getEntryPoint().toString());row.addProperty("name",f.getName());row.addProperty("signature",f.getSignature().toString());row.addProperty("body",f.getBody().toString());row.addProperty("source",f.getSymbol().getSource().toString());row.addProperty("external",f.isExternal());row.addProperty("thunk",f.isThunk());
   var digest=MessageDigest.getInstance("SHA-256");var ins=currentProgram.getListing().getInstructions(f.getBody(),true);int count=0;var flows=new JsonArray();while(ins.hasNext()){var i=ins.next();count++;digest.update(i.getAddress().toString().getBytes(java.nio.charset.StandardCharsets.UTF_8));digest.update(i.getBytes());if(i.getFlowType().isFlow()||i.getFlowOverride()!=FlowOverride.NONE){var flow=new JsonObject();flow.addProperty("address",i.getAddress().toString());flow.addProperty("override",i.getFlowOverride().toString());var refs=new JsonArray();for(var ref:i.getReferencesFrom())if(ref.getReferenceType().isFlow())refs.add(ref.getToAddress()+":"+ref.getReferenceType());flow.add("targets",refs);flows.add(flow);}}
   row.addProperty("instruction_count",count);row.addProperty("byte_hash",HexFormat.of().formatHex(digest.digest()));row.add("flows",flows);
   var vars=new JsonArray();for(var v:f.getAllVariables()){var x=new JsonObject();x.addProperty("name",v.getName());x.addProperty("type",v.getDataType().getPathName());x.addProperty("storage",v.getVariableStorage().toString());x.addProperty("parameter",v instanceof Parameter);vars.add(x);}row.add("variables",vars);
   var callees=new JsonArray();for(var c:f.getCalledFunctions(monitor))callees.add(c.getEntryPoint().toString());row.add("callees",callees);functions.add(row);
  }result.add("functions",functions);
  var symbols=new JsonArray();var si=currentProgram.getSymbolTable().getAllSymbols(true);while(si.hasNext()){monitor.checkCancelled();var s=si.next();var row=new JsonObject();row.addProperty("id",s.getID());row.addProperty("address",s.getAddress().toString());row.addProperty("name",s.getName());row.addProperty("kind",s.getSymbolType().toString());row.addProperty("namespace",s.getParentNamespace().getName(true));row.addProperty("primary",s.isPrimary());symbols.add(row);}result.add("symbols",symbols);
  var types=new JsonArray();var ti=currentProgram.getDataTypeManager().getAllDataTypes();while(ti.hasNext()){monitor.checkCancelled();var t=ti.next();var row=new JsonObject();row.addProperty("path",t.getPathName());row.addProperty("length",t.getLength());row.addProperty("definition",t.toString());types.add(row);}result.add("types",types);
  var strings=new JsonArray();var di=currentProgram.getListing().getDefinedData(true);while(di.hasNext()){var d=di.next();if(d.hasStringValue()){var row=new JsonObject();row.addProperty("address",d.getAddress().toString());row.addProperty("value",String.valueOf(d.getValue()));strings.add(row);}}result.add("strings",strings);
  result.addProperty("schema_version",1);result.addProperty("collector_version",1);result.addProperty("complete",true);println("CAMPAIGN_RESULT:"+result);
 }
}
