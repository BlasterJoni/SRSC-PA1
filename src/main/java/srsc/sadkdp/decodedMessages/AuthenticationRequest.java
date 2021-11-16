package srsc.sadkdp.decodedMessages;

public class AuthenticationRequest {
    private String n1, salt, counter;

    public AuthenticationRequest(String n1, String salt, String counter) {
        this.n1 = n1;
        this.salt = salt;
        this.counter = counter;
    }

    public String getN1() {
        return this.n1;
    }

    public void setN1(String n1) {
        this.n1 = n1;
    }

    public String getSalt() {
        return this.salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    public String getCounter() {
        return this.counter;
    }

    public void setCounter(String counter) {
        this.counter = counter;
    }

}