package srsc.sadkdp.decodedMessages;

public class PaymentRequest {
    private String n2_, n3, price, integrityCheck4;

    public PaymentRequest(String n2_, String n3, String price, String integrityCheck4) {
        this.n2_ = n2_;
        this.n3 = n3;
        this.price = price;
        this.integrityCheck4 = integrityCheck4;
    }

    public String getN2_() {
        return this.n2_;
    }

    public void setN2_(String n2_) {
        this.n2_ = n2_;
    }

    public String getN3() {
        return this.n3;
    }

    public void setN3(String n3) {
        this.n3 = n3;
    }

    public String getPrice() {
        return this.price;
    }

    public void setPrice(String price) {
        this.price = price;
    }

    public String getIntegrityCheck4() {
        return this.integrityCheck4;
    }

    public void setIntegrityCheck4(String integrityCheck4) {
        this.integrityCheck4 = integrityCheck4;
    }

    
}