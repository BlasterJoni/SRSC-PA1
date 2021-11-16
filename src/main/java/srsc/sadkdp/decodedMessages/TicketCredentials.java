package srsc.sadkdp.decodedMessages;

public class TicketCredentials {
    private String ip, port, movieId, ciphersuiteConf, cryptoSA, sessionKey, macKey, n4_, integrityCheck6;
    private byte[] serverTicket;

    public TicketCredentials(String ip, String port, String movieId, String ciphersuiteConf, String cryptoSA, String sessionKey, String macKey, String n4_, String integrityCheck6, byte[] serverTicket) {
        this.ip = ip;
        this.port = port;
        this.movieId = movieId;
        this.ciphersuiteConf = ciphersuiteConf;
        this.cryptoSA = cryptoSA;
        this.sessionKey = sessionKey;
        this.macKey = macKey;
        this.n4_ = n4_;
        this.integrityCheck6 = integrityCheck6;
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

    public String getSessionKey() {
        return this.sessionKey;
    }

    public void setSessionKey(String sessionKey) {
        this.sessionKey = sessionKey;
    }

    public String getMacKey() {
        return this.macKey;
    }

    public void setMacKey(String macKey) {
        this.macKey = macKey;
    }

    public String getN4_() {
        return this.n4_;
    }

    public void setN4_(String n4_) {
        this.n4_ = n4_;
    }

    public String getIntegrityCheck6() {
        return this.integrityCheck6;
    }

    public void setIntegrityCheck6(String integrityCheck6) {
        this.integrityCheck6 = integrityCheck6;
    }

    public byte[] getServerTicket() {
        return this.serverTicket;
    }

    public void setServerTicket(byte[] serverTicket) {
        this.serverTicket = serverTicket;
    }

    
}