package srsc.configEntities;

import srsc.Utils;

public class Confidentiality {
    private String spec;
    private String key;
    private String keyspec;
    private String iv;

    public Confidentiality() {
    }

    public Confidentiality(String spec, String key, String keyspec, String iv) {
        this.spec = spec;
        this.key = key;
        this.keyspec = keyspec;
        this.iv = iv;
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

    public byte[] getKeyByte() {
        return Utils.hexStringToByteArray(this.key);
    }

    public void setKeyByte(byte[] key) {
        this.key = Utils.toHex(key);
    }

    public String getKeySpec() {
        return this.keyspec;
    }

    public void setKeySpec(String keyspec) {
        this.key = keyspec;
    }

    public String getIv() {
        return this.iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public byte[] getIvByte() {
        return Utils.hexStringToByteArray(this.iv);
    }

    public void setIvByte(byte[] iv) {
        this.iv = Utils.toHex(iv);
    }

}
