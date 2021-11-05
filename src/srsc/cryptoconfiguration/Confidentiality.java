package srsc.cryptoconfiguration;

public class Confidentiality {
    private String spec;
    private int keysize;
    private String key;
    private byte[] iv;

    public Confidentiality() {
    }

    public Confidentiality(String spec, int keysize, String key, byte[] iv) {
        this.spec = spec;
        this.keysize = keysize;
        this.key = key;
        this.iv = iv;
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

    public String getKey() {
        return this.key;
    }

    public void setKey(String key) {
        this.key = key;
    }

    public byte[] getIv() {
        return this.iv;
    }

    public void setIv(byte[] iv) {
        this.iv = iv;
    }

}
