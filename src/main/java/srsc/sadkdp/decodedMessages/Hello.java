package srsc.sadkdp.decodedMessages;

public class Hello {
    private String userId, proxyBoxId;

    public Hello(String userId, String proxyBoxId){
        this.userId = userId;
        this.proxyBoxId = proxyBoxId;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getProxyBoxId() {
        return this.proxyBoxId;
    }

    public void setProxyBoxId(String proxyBoxId) {
        this.proxyBoxId = proxyBoxId;
    }
   
}
