package srsc.configEntities;

import com.google.gson.Gson;

import srsc.Utils;

public class SignedCoin {

    private Coin coin;
    private String coinPublicKey;
    private String coinAuthenticity;

    public SignedCoin(){
    }

    public SignedCoin(Coin coin, byte[] coinPublicKey, byte[] coinAuthenticity){
        this.coin = coin;
        this.coinPublicKey = Utils.toHex(coinPublicKey);
        this.coinAuthenticity = Utils.toHex(coinAuthenticity);
    }

    public Coin getCoin() {
        return this.coin;
    }

    public void setCoin(Coin coin) {
        this.coin = coin;
    }

    public byte[] getCoinPublicKey() {
        return Utils.hexStringToByteArray(this.coinPublicKey);
    }

    public void setCoinPublicKey(byte[] coinPublicKey) {
        this.coinPublicKey = Utils.toHex(coinPublicKey);
    }

    public byte[] getCoinAuthenticity() {
        return Utils.hexStringToByteArray(this.coinAuthenticity);
    }

    public void setCoinAuthenticity(byte[] coinAuthenticity) {
        this.coinAuthenticity = Utils.toHex(coinAuthenticity);
    }

    public byte[] toByteArray(){
        Gson gson = new Gson();
        String c = gson.toJson(this);
        return Utils.toByteArray(c);
    }

    
}
