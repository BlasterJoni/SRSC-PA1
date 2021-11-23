package srsc.sadkdp.jsonEntities;

import srsc.configEntities.CoinWithIntegrity;

public class Payment {
    private CoinWithIntegrity paymentCoin;
    private int n3_, n4;

    public Payment(){
    }

    public Payment(int n3_, int n4, CoinWithIntegrity paymentCoin) {
        this.n3_ = n3_;
        this.n4 = n4;
        this.paymentCoin = paymentCoin;
    }

    public int getN3_() {
        return this.n3_;
    }

    public void setN3_(int n3_) {
        this.n3_ = n3_;
    }

    public int getN4() {
        return this.n4;
    }

    public void setN4(int n4) {
        this.n4 = n4;
    }

    public CoinWithIntegrity getPaymentCoin() {
        return this.paymentCoin;
    }

    public void setPaymentCoin(CoinWithIntegrity paymentCoin) {
        this.paymentCoin = paymentCoin;
    }
}