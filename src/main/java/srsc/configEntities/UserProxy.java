package srsc.configEntities;

public class UserProxy {
    private String userId, password, proxyBoxID;

    public UserProxy() {
    }

    public UserProxy(String userId, String password, String proxyId) {
        this.userId = userId;
        this.password = password;
        this.proxyBoxID = proxyId;
    }

    public String getUserId() {
        return this.userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getPassword() {
        return this.password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    public String getProxyId() {
        return this.proxyBoxID;
    }

    public void setProxyId(String proxyId) {
        this.proxyBoxID = proxyId;
    }

}
