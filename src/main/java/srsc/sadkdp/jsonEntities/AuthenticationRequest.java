package srsc.sadkdp.jsonEntities;

public class AuthenticationRequest {
    private int n1, counter;
    private byte[] salt;

    public AuthenticationRequest(){
    }

    public AuthenticationRequest(int n1, byte[] salt, int counter) {
        this.n1 = n1;
        this.salt = salt;
        this.counter = counter;
    }

    public int getN1() {
        return this.n1;
    }

    public void setN1(int n1) {
        this.n1 = n1;
    }

    public byte[] getSalt() {
        return this.salt;
    }

    public void setSalt(byte[] salt) {
        this.salt = salt;
    }

    public int getCounter() {
        return this.counter;
    }

    public void setCounter(int counter) {
        this.counter = counter;
    }

}