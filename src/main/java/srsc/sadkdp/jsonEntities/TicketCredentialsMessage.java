package srsc.sadkdp.jsonEntities;

public class TicketCredentialsMessage {
    private byte[] ticketForProxyBox;
    private byte[] ticketForStreamingServer;
    private byte[] signature;

    public TicketCredentialsMessage(){
    }

    public TicketCredentialsMessage(byte[] ticketForProxyBox, byte[] ticketForStreamingServer, byte[] signature){
        this.ticketForProxyBox = ticketForProxyBox;
        this.ticketForStreamingServer = ticketForStreamingServer;
        this.signature = signature;
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

    public byte[] getSignature() {
        return this.signature;
    }

    public void setSignature(byte[] signature) {
        this.signature = signature;
    }
    
}
