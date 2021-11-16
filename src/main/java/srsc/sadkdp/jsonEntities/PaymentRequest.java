package srsc.sadkdp.jsonEntities;

public class PaymentRequest {
    private int n2_, n3, price;

    public PaymentRequest() {
    }

    public PaymentRequest(int price, int n2_, int n3) {
        this.price = price;
        this.n2_ = n2_;
        this.n3 = n3;
    }

    public int getN2_() {
        return this.n2_;
    }

    public void setN2_(int n2_) {
        this.n2_ = n2_;
    }

    public int getN3() {
        return this.n3;
    }

    public void setN3(int n3) {
        this.n3 = n3;
    }

    public int getPrice() {
        return this.price;
    }

    public void setPrice(int price) {
        this.price = price;
    }
    
}