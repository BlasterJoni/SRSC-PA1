package srsc.srtsp.jsonEntities;

public class RequestAndCredentials {
    private int n1;
    private TicketCredentials ticketCredentials;

    public RequestAndCredentials() {
    }

    public RequestAndCredentials(TicketCredentials ticketCredentials, int n1) {
        this.ticketCredentials = ticketCredentials;
        this.n1 = n1;
    }

    public int getN1() {
        return this.n1;
    }

    public void setN1(int n1) {
        this.n1 = n1;
    }

    public TicketCredentials getTicketCredentials() {
        return this.ticketCredentials;
    }

    public void setTicketCredentials(TicketCredentials ticketCredentials) {
        this.ticketCredentials = ticketCredentials;
    }
}