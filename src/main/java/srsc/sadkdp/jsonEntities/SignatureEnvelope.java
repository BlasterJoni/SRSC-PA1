package srsc.sadkdp.jsonEntities;

public class SignatureEnvelope {

    private byte[] payload;
    private byte[] sigBytes;

    public SignatureEnvelope() {
    }

    public SignatureEnvelope(byte[] payload, byte[] sigBytes) {
        this.payload = payload;
        this.sigBytes = sigBytes;
    }

    public byte[] getPayload() {
        return this.payload;
    }

    public void setPayload(byte[] payload) {
        this.payload = payload;
    }

    public byte[] getSigBytes() {
        return this.sigBytes;
    }

    public void setSigBytes(byte[] sigBytes) {
        this.sigBytes = sigBytes;
    }


}
