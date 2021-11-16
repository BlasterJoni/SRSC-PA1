package srsc.sadkdp.decodedMessages;

public class Payment {
    private String n3_, n4, paymentCoin, integrityCheck5;

    public Payment(String n3_, String n4, String paymentCoin, String integrityCheck5) {
        this.n3_ = n3_;
        this.n4 = n4;
        this.paymentCoin = paymentCoin;
        this.integrityCheck5 = integrityCheck5;
    }

    public String getN3_() {
        return this.n3_;
    }

    public void setN3_(String n3_) {
        this.n3_ = n3_;
    }

    public String getN4() {
        return this.n4;
    }

    public void setN4(String n4) {
        this.n4 = n4;
    }

    public String getPaymentCoin() {
        return this.paymentCoin;
    }

    public void setPaymentCoin(String paymentCoin) {
        this.paymentCoin = paymentCoin;
    }

    public String getIntegrityCheck5() {
        return this.integrityCheck5;
    }

    public void setIntegrityCheck5(String integrityCheck5) {
        this.integrityCheck5 = integrityCheck5;
    }


}