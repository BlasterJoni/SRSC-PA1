package srsc.srtsp.jsonEntities;

public class RequestAndCredentialsSend {
    private int n1;
    private byte[] ticketCredentials, signature;

    public RequestAndCredentialsSend() {
    }

    public RequestAndCredentialsSend(byte[] ticketCredentials, byte[] signature, int n1) {
        this.ticketCredentials = ticketCredentials;
        this.signature = signature;
        this.n1 = n1;
    }

    public byte[] getTicketCredentials() {
        return this.ticketCredentials;
    }

    public void setTicketCredentials(byte[] ticketCredentials) {
        this.ticketCredentials = ticketCredentials;
    }

    public byte[] getSignature() {
        return this.signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }

    public int getN1() {
        return this.n1;
    }

    public void setN1(int n1) {
        this.n1 = n1;
    }
}