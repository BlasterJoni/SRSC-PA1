package srsc.configEntities;

import srsc.Utils;

public class Integrity {

   private String spec;
   private String key;
   private String keyspec;

    public Integrity(){
    }

   public Integrity(String spec, String key, String keyspec){
       this.spec = spec;
       this.key = key;
       this.keyspec = keyspec;
   }

    public String getSpec() {
        return this.spec;
    }

    public void setSpec(String spec) {
        this.spec = spec;
    }

    public String getKey() {
        return this.key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public String getKeySpec() {
        return this.keyspec;
    }

    public void setKeySpec(String keyspec) {
        this.key = keyspec;
    }

    public byte[] getKeyByte() {
        return Utils.hexStringToByteArray(this.key);
    }

    public void setKeyByte(byte[] key) {
        this.key = Utils.toHex(key);
    }

}
