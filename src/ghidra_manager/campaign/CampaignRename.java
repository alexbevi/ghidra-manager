import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.data.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
public class CampaignRename extends GhidraScript {
 Map<String,Symbol> globals=new HashMap<>();
 DataTypeComponent field(JsonObject c)throws Exception{
  var type=currentProgram.getDataTypeManager().getDataType(c.get("address").getAsString());
  if(!(type instanceof Structure))throw new Exception("Missing structure");
  DataTypeComponent found=null;
  for(var component:((Structure)type).getDefinedComponents())if(component.getOffset()==c.get("offset").getAsInt()){
   if(found!=null||component.isBitFieldComponent())throw new Exception("Ambiguous or bitfield component");found=component;
  }
  if(found==null)throw new Exception("Missing defined component");return found;
 }
 Variable variable(JsonObject c)throws Exception{
  var f=getFunctionAt(toAddr(c.get("address").getAsString()));if(f==null)throw new Exception("Missing owning function");Variable found=null;
  for(var v:f.getAllVariables())if(v.getVariableStorage().toString().equals(c.get("storage").getAsString())&&(v instanceof Parameter)==c.get("kind").getAsString().equals("parameter")){if(found!=null)throw new Exception("Ambiguous storage");found=v;}
  if(found==null)throw new Exception("No persistent variable");return found;
 }
 String name(JsonObject c)throws Exception{
  if(c.get("kind").getAsString().equals("field"))return field(c).getFieldName();
  String kind=c.get("kind").getAsString();if(kind.equals("function")){var f=getFunctionAt(toAddr(c.get("address").getAsString()));if(f==null)throw new Exception("Missing function");return f.getName();}
  if(kind.equals("global")){var s=globals.get(c.get("address").getAsString());if(s==null||!s.getAddress().equals(toAddr(c.get("address").getAsString()))||!s.isGlobal()||s.getSymbolType()!=SymbolType.LABEL)throw new Exception("Missing global");return s.getName();}
  if(kind.equals("local")||kind.equals("parameter"))return variable(c).getName();throw new Exception("Unsupported rename kind");
 }
 public void run()throws Exception{
  var config=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();var plan=config.getAsJsonObject("plan");var identity=plan.getAsJsonObject("identity");
  if(!currentProgram.getExecutableSHA256().equals(identity.get("digest").getAsString())||!currentProgram.getDomainFile().getPathname().equals(identity.get("program_path").getAsString()))throw new Exception("Program identity changed");
  var changes=plan.getAsJsonArray("changes");String id=plan.get("id").getAsString();var journal=currentProgram.getOptions("GhidraManagerCampaign");boolean already=journal.getString(id,"").equals("applied");
  // Dynamic labels receive a persistent ID on rename. Retain the actual object,
  // and resolve receipt-backed replays by exact global name and address.
  for(var e:changes){var c=e.getAsJsonObject();if(!c.get("kind").getAsString().equals("global"))continue;String address=c.get("address").getAsString();Symbol s=null;
   if(already){for(var candidate:currentProgram.getSymbolTable().getSymbols(toAddr(address)))if(candidate.isGlobal()&&candidate.getSymbolType()==SymbolType.LABEL&&candidate.getName().equals(c.get("new_name").getAsString())){if(s!=null)throw new Exception("Ambiguous renamed global");s=candidate;}}
   else s=currentProgram.getSymbolTable().getSymbol(c.get("symbol_id").getAsLong());
   globals.put(address,s);
  }
  for(var e:changes){var c=e.getAsJsonObject();if(!name(c).equals(c.get(already?"new_name":"old_name").getAsString()))throw new Exception("Stale rename target");}
  boolean committed=already;int tx=currentProgram.startTransaction("Ghidra Manager rename "+id);
  try{
   if(!already)for(var c:changes){var change=c.getAsJsonObject();if(change.get("kind").getAsString().equals("field")){
    var type=currentProgram.getDataTypeManager().getDataType(change.get("address").getAsString());JsonObject expected=null;
    for(var e:config.getAsJsonObject("before").getAsJsonArray("types")){var row=e.getAsJsonObject();if(row.get("path").getAsString().equals(change.get("address").getAsString()))expected=row;}
    if(expected==null||!type.toString().equals(expected.get("definition").getAsString())||type.getLength()!=expected.get("length").getAsInt())throw new Exception("Structure changed before transaction");
    var components=((Structure)type).getDefinedComponents();var fields=expected.getAsJsonArray("fields");
    if(components.length!=fields.size())throw new Exception("Structure components changed");
    for(int i=0;i<components.length;i++){var component=components[i];var row=fields.get(i).getAsJsonObject();
     if(component.getOffset()!=row.get("offset").getAsInt()||component.getLength()!=row.get("length").getAsInt()||!component.getDataType().getPathName().equals(row.get("type").getAsString())||!Objects.equals(component.getFieldName(),row.get("name").isJsonNull()?null:row.get("name").getAsString()))throw new Exception("Structure component metadata changed");
    }
   }else if(!change.get("kind").getAsString().equals("global")){
    var f=getFunctionAt(toAddr(change.get("address").getAsString()));JsonObject expected=null;for(var e:config.getAsJsonObject("before").getAsJsonArray("functions")){var row=e.getAsJsonObject();if(row.get("address").getAsString().equals(change.get("address").getAsString()))expected=row;}
    if(expected==null||!f.getBody().toString().equals(expected.get("body").getAsString())||!f.getSignature().toString().equals(expected.get("signature").getAsString()))throw new Exception("Target metadata changed before transaction");
    var digest=java.security.MessageDigest.getInstance("SHA-256");var iter=currentProgram.getListing().getInstructions(f.getBody(),true);while(iter.hasNext()){var i=iter.next();digest.update(i.getAddress().toString().getBytes(StandardCharsets.UTF_8));digest.update(i.getBytes());}if(!HexFormat.of().formatHex(digest.digest()).equals(expected.get("byte_hash").getAsString()))throw new Exception("Target bytes changed");
   }}
   if(!already)for(var e:changes){monitor.checkCancelled();var c=e.getAsJsonObject();String n=c.get("new_name").getAsString();String kind=c.get("kind").getAsString();if(!n.matches("[A-Za-z_][A-Za-z0-9_]*"))throw new Exception("Invalid name");
    if(kind.equals("function"))getFunctionAt(toAddr(c.get("address").getAsString())).setName(n,SourceType.USER_DEFINED);
    else if(kind.equals("global"))globals.get(c.get("address").getAsString()).setName(n,SourceType.USER_DEFINED);
    else if(kind.equals("field"))field(c).setFieldName(n);
    else variable(c).setName(n,SourceType.USER_DEFINED);
   }
   for(var e:changes){var c=e.getAsJsonObject();if(!name(c).equals(c.get("new_name").getAsString()))throw new Exception("Readback mismatch");}
   journal.setString(id,"applied");committed=true;
  }finally{currentProgram.endTransaction(tx,committed);}
  var result=new JsonObject();result.addProperty("complete",true);result.addProperty("transaction",id);result.addProperty("committed",committed);result.addProperty("already_applied",already);java.nio.file.Files.writeString(java.nio.file.Path.of(config.get("output").getAsString()),result.toString());println("CAMPAIGN_RESULT:complete");
 }
}
