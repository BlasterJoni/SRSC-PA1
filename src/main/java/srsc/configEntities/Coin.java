package srsc.configEntities;

import com.google.gson.Gson;

import srsc.Utils;

public class Coin {

    private String name;
    private String coinIssuer;
    private int coinValue;
    private String expireDate;

    public Coin(){
    }

    public Coin(String name, String coinIssuer, int coinValue, String expireDate){
        this.name = name;
        this.coinIssuer = coinIssuer;
        this.coinValue = coinValue;
        this.expireDate = expireDate;
    }

    public String getName() {
        return this.name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getCoinIssuer() {
        return this.coinIssuer;
    }

    public void setCoinIssuer(String coinIssuer) {
        this.coinIssuer = coinIssuer;
    }

    public int getCoinValue() {
        return this.coinValue;
    }

    public void setCoinValue(int coinValue) {
        this.coinValue = coinValue;
    }

    public String getExpireDate() {
        return this.expireDate;
    }

    public void setExpireDate(String expireDate) {
        this.expireDate = expireDate;
    }


    public byte[] toByteArray(){
        Gson gson = new Gson();
        String c = gson.toJson(this);
        return Utils.toByteArray(c);
    }
    
}
