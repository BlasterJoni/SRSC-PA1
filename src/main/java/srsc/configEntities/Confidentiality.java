package srsc.configEntities;

import srsc.Utils;

public class Confidentiality {
    private String spec;
    private String key;
    private String keyspec;
    private String iv;

    public Confidentiality() {
    }

    public Confidentiality(String spec, byte[] key, String keyspec, byte[] iv) {
        this.spec = spec;
        this.key = Utils.toHex(key);
        this.keyspec = keyspec;
        this.iv = Utils.toHex(iv);
    }
    
    public String getSpec() {
        return this.spec;
    }

    public void setSpec(String spec) {
        this.spec = spec;
    }

    public byte[] getKey() {
        return Utils.hexStringToByteArray(this.key);
    }

    public void setKey(byte[] key) {
        this.key = Utils.toHex(key);
    }

    public String getKeySpec() {
        return this.keyspec;
    }

    public void setKeySpec(String keyspec) {
        this.key = keyspec;
    }

    public byte[] getIv() {
        return Utils.hexStringToByteArray(this.iv);
    }

    public void setIv(byte[] iv) {
        this.iv = Utils.toHex(iv);
    }

}
