import ghidra.app.script.GhidraScript;
import ghidra.program.model.data.*;
import java.util.*;
import java.nio.charset.StandardCharsets;
import com.google.gson.*;
public class CampaignTypes extends GhidraScript {
 DataType type(String path)throws Exception{var t=currentProgram.getDataTypeManager().getDataType(path);if(t==null)t=BuiltInDataTypeManager.getDataTypeManager().getDataType(path);if(t==null)throw new Exception("Unknown type "+path);return t;}
 public void run()throws Exception{
  var config=JsonParser.parseString(new String(Base64.getDecoder().decode(getScriptArgs()[0]),StandardCharsets.UTF_8)).getAsJsonObject();var plan=config.getAsJsonObject("plan");
  if(!currentProgram.getExecutableSHA256().equals(plan.getAsJsonObject("identity").get("digest").getAsString()))throw new Exception("Digest mismatch");
  String id=plan.get("id").getAsString();var journal=currentProgram.getOptions("GhidraManagerCampaign");if(!journal.getString(id,"").isEmpty())throw new Exception("Reconcile existing type transaction");
  int tx=currentProgram.startTransaction("Ghidra Manager layouts "+id);boolean committed=false;
  try{for(var e:plan.getAsJsonArray("changes")){monitor.checkCancelled();var c=e.getAsJsonObject();String kind=c.get("kind").getAsString();
    if(kind.equals("structure")){String path=c.get("path").getAsString();if(currentProgram.getDataTypeManager().getDataType(path)!=null)throw new Exception("Existing structure conflicts");int split=path.lastIndexOf('/');var s=new StructureDataType(new CategoryPath(split==0?"/":path.substring(0,split)),path.substring(split+1),c.get("length").getAsInt());
     for(var field:c.getAsJsonArray("fields")){var f=field.getAsJsonObject();var t=type(f.get("type").getAsString());int length=f.get("length").getAsInt();if(t.getLength()!=length)throw new Exception("Field type extent mismatch");s.replaceAtOffset(f.get("offset").getAsInt(),t,length,f.get("name").getAsString(),null);}currentProgram.getDataTypeManager().addDataType(s,DataTypeConflictHandler.KEEP_HANDLER);
    }else if(kind.equals("data_type")){var a=toAddr(c.get("address").getAsString());var t=type(c.get("type").getAsString());int length=c.get("length").getAsInt();if(t.getLength()!=length)throw new Exception("Data extent mismatch");var end=a.add(length-1);
     for(int n=0;n<length;n++){var at=a.add(n);if(getInstructionContaining(at)!=null||getFunctionContaining(at)!=null)throw new Exception("Data overlaps code");var d=currentProgram.getListing().getDefinedDataContaining(at);if(d!=null&&(d.getMinAddress().compareTo(a)<0||d.getMaxAddress().compareTo(end)>0))throw new Exception("Partial data overlap");}clearListing(a,end);createData(a,t);
    }else throw new Exception("Unsupported layout operation");
   }journal.setString(id,"applied");committed=true;
  }finally{currentProgram.endTransaction(tx,committed);}
  var result=new JsonObject();result.addProperty("complete",true);result.addProperty("committed",committed);result.addProperty("transaction",id);java.nio.file.Files.writeString(java.nio.file.Path.of(config.get("output").getAsString()),result.toString());println("CAMPAIGN_RESULT:complete");
 }
}
