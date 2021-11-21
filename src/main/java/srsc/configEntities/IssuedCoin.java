package srsc.configEntities;

import com.google.gson.Gson;

import srsc.Utils;

public class IssuedCoin {

    private SignedCoin signedCoin;
    private String issueSignature;
    private String issuePublicKey;

    public IssuedCoin() {
    }

    public IssuedCoin(SignedCoin signedCoin, byte[] issuePublicKey, byte[] issueSignature) {
        this.signedCoin = signedCoin;
        this.issueSignature = Utils.toHex(issueSignature);
        this.issuePublicKey = Utils.toHex(issuePublicKey);
    }

    public SignedCoin getSignedCoin() {
        return this.signedCoin;
    }

    public void setSignedCoin(SignedCoin signedCoin) {
        this.signedCoin = signedCoin;
    }

    public byte[] getIssueSignature() {
        return Utils.hexStringToByteArray(this.issueSignature);
    }

    public void setIssueSignature(byte[] issueSignature) {
        this.issueSignature = Utils.toHex(issueSignature);
    }

    public byte[] getIssuePublicKey() {
        return Utils.hexStringToByteArray(this.issuePublicKey);
    }

    public void setIssuePublicKey(byte[] issuePublicKey) {
        this.issuePublicKey = Utils.toHex(issuePublicKey);
    }

    public byte[] toByteArray(){
        Gson gson = new Gson();
        String c = gson.toJson(this);
        return Utils.toByteArray(c);
    }

}
