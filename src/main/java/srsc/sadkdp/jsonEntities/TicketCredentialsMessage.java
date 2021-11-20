package srsc.sadkdp.jsonEntities;

public class TicketCredentialsMessage {
    private byte[] ticketForProxyBox;
    private byte[] ticketForStreamingServer;
    private byte[] signatureProxyBox, signatureStreamingServer;

    public TicketCredentialsMessage(){
    }

    public TicketCredentialsMessage(byte[] ticketForProxyBox, byte[] ticketForStreamingServer, byte[] signatureProxyBox, byte[] signatureStreamingServer){
        this.ticketForProxyBox = ticketForProxyBox;
        this.ticketForStreamingServer = ticketForStreamingServer;
        this.signatureProxyBox = signatureProxyBox;
        this.signatureStreamingServer = signatureStreamingServer;
    }

    public byte[] getTicketForProxyBox() {
        return this.ticketForProxyBox;
    }

    public void setTicketForProxyBox(byte[] ticketForProxyBox) {
        this.ticketForProxyBox = ticketForProxyBox;
    }

    public byte[] getTicketForStreamingServer() {
        return this.ticketForStreamingServer;
    }

    public void setTicketForStreamingServer(byte[] ticketForStreamingServer) {
        this.ticketForStreamingServer = ticketForStreamingServer;
    }

    public byte[] getSignatureProxyBox() {
        return this.signatureProxyBox;
    }

    public void setSignatureProxyBox(byte[] signatureProxyBox) {
        this.signatureProxyBox = signatureProxyBox;
    }

    public byte[] getSignatureStreamingServer() {
        return this.signatureStreamingServer;
    }

    public void setSignatureStreamingServer(byte[] signatureStreamingServer) {
        this.signatureStreamingServer = signatureStreamingServer;
    }
    
}
