package srsc.sadkdp.jsonEntities;

import srsc.configEntities.Ciphersuite;

public class TicketCredentialsReturn {
    private String ip, port, movieId;
    private Ciphersuite ciphersuiteConf;
    private int n4_;
    private byte[] sessionKey, sessionIV, streamTicket, streamSigBytes, macKey;

    public TicketCredentialsReturn() {
    }

    public TicketCredentialsReturn(String ip, String port, String movieId, Ciphersuite ciphersuiteConf, byte[] sessionKey, byte[] sessionIV, byte[] macKey, int n4_, byte[] streamTicket, byte[] streamSigBytes) {
        this.ip = ip;
        this.port = port;
        this.movieId = movieId;
        this.ciphersuiteConf = ciphersuiteConf;
        this.sessionKey = sessionKey;
        this.streamTicket = streamTicket;
        this.streamSigBytes = streamSigBytes;
        this.sessionIV = sessionIV;
        this.macKey = macKey;
        this.n4_ = n4_;
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

    public Ciphersuite getCiphersuiteConf() {
        return this.ciphersuiteConf;
    }

    public void setCiphersuiteConf(Ciphersuite ciphersuiteConf) {
        this.ciphersuiteConf = ciphersuiteConf;
    }

    public int getN4_() {
        return this.n4_;
    }

    public void setN4_(int n4_) {
        this.n4_ = n4_;
    }

    public byte[] getSessionKey() {
        return this.sessionKey;
    }

    public void setSessionKey(byte[] sessionKey) {
        this.sessionKey = sessionKey;
    }

    public byte[] getSessionIV() {
        return this.sessionIV;
    }

    public void setSessionIV(byte[] sessionIV) {
        this.sessionIV = sessionIV;
    }

    public byte[] getStreamTicket() {
        return this.streamTicket;
    }

    public void setStreamTicket(byte[] streamTicket) {
        this.streamTicket = streamTicket;
    }

     public byte[] getStreamSigBytes() {
        return this.streamSigBytes;
    }

    public void setStreamSigBytes(byte[] streamSigBytes) {
        this.streamSigBytes = streamSigBytes;
    }

    public byte[] getMacKey() {
        return this.macKey;
    }

    public void setMacKey(byte[] macKey) {
        this.macKey = macKey;
    }
    
    
    
}