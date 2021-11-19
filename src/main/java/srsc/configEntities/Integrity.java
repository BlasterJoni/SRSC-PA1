package srsc.configEntities;

public class Integrity {

   private String spec;
   private int keysize;
   private byte[] key;

    public Integrity(){
    }

   public Integrity(String spec, int keysize, byte[] key){
       this.spec = spec;
       this.keysize = keysize;
       this.key = key;
   }

    public String getSpec() {
        return this.spec;
    }

    public void setSpec(String spec) {
        this.spec = spec;
    }

    public int getKeysize() {
        return this.keysize;
    }

    public void setKeysize(int keysize) {
        this.keysize = keysize;
    }

    public byte[] getKey() {
        return this.key;
    }

    public void setKey(byte[] key) {
        this.key = key;
    }

}
