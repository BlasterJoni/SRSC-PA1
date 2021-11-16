package srsc.sadkdp.jsonEntities;

public class TicketCredentials {
    private String ip, port, movieId, ciphersuiteConf, cryptoSA;
    private int n4_;
    private byte[] sessionKey, macKey, serverTicket;

    public TicketCredentials() {
    }

    public TicketCredentials(String ip, String port, String movieId, String ciphersuiteConf, String cryptoSA, byte[] sessionKey, byte[] macKey, int n4_, byte[] serverTicket) {
        this.ip = ip;
        this.port = port;
        this.movieId = movieId;
        this.ciphersuiteConf = ciphersuiteConf;
        this.cryptoSA = cryptoSA;
        this.sessionKey = sessionKey;
        this.macKey = macKey;
        this.n4_ = n4_;
        this.serverTicket = serverTicket;
    }

    public String getIp() {
        return this.ip;
    }

    public void setIp(String ip) {
        this.ip = ip;
    }

    public String getPort() {
        return this.port;
    }

    public void setPort(String port) {
        this.port = port;
    }

    public String getMovieId() {
        return this.movieId;
    }

    public void setMovieId(String movieId) {
        this.movieId = movieId;
    }

    public String getCiphersuiteConf() {
        return this.ciphersuiteConf;
    }

    public void setCiphersuiteConf(String ciphersuiteConf) {
        this.ciphersuiteConf = ciphersuiteConf;
    }

    public String getCryptoSA() {
        return this.cryptoSA;
    }

    public void setCryptoSA(String cryptoSA) {
        this.cryptoSA = cryptoSA;
    }

    public byte[] getSessionKey() {
        return this.sessionKey;
    }

    public void setSessionKey(byte[] sessionKey) {
        this.sessionKey = sessionKey;
    }

    public byte[] getMacKey() {
        return this.macKey;
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = macKey;
    }

    public int getN4_() {
        return this.n4_;
    }

    public void setN4_(int n4_) {
        this.n4_ = n4_;
    }

    public byte[] getServerTicket() {
        return this.serverTicket;
    }

    public void setServerTicket(byte[] serverTicket) {
        this.serverTicket = serverTicket;
    }

    
}