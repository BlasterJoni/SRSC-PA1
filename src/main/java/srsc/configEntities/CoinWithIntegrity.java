package srsc.configEntities;

import com.google.gson.Gson;

import srsc.Utils;

public class CoinWithIntegrity {
    
    private IssuedCoin issuedCoin;
    private String integrityProof1;
    private String integrityProof2;

    public CoinWithIntegrity(){
    }

    public CoinWithIntegrity(IssuedCoin issuedCoin, byte[] integrityProof1, byte[] integrityProof2){
        this.issuedCoin = issuedCoin;
        this.integrityProof1 = Utils.toHex(integrityProof1);
        this.integrityProof2 = Utils.toHex(integrityProof2);
    }

    public byte[] getIntegrityProof1() {
        return Utils.hexStringToByteArray(this.integrityProof1);
    }

    public void setIntegrityProof1(byte[] integrityProof1) {
        this.integrityProof1 = Utils.toHex(integrityProof1);
    }

    public byte[] getIntegrityProof2() {
        return Utils.hexStringToByteArray(this.integrityProof2);
    }

    public void setIntegrityProof2(byte[] integrityProof2) {
        this.integrityProof2 = Utils.toHex(integrityProof2);
    }

    public IssuedCoin getIssuedCoin() {
        return this.issuedCoin;
    }

    public void setIssuedCoin(IssuedCoin issuedCoin) {
        this.issuedCoin = issuedCoin;
    }

    public byte[] toByteArray(){
        Gson gson = new Gson();
        String c = gson.toJson(this);
        return Utils.toByteArray(c);
    }

}
