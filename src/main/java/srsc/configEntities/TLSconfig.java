package srsc.configEntities;

public class TLSconfig {
    private String authentication;
    private String version;
    private String[] ciphersuites;

    public TLSconfig(){
    }

    public TLSconfig(String authentication, String tlsversion, String[] ciphersuites) {
        this.authentication = authentication;
        this.version = tlsversion;
        this.ciphersuites = ciphersuites;
    }

    public String getAuthentication() {
        return this.authentication;
    }

    public void setAuthentication(String authentication) {
        this.authentication = authentication;
    }

    public String getVersion() {
        return this.version;
    }

    public void setVersion(String version) {
        this.version = version;
    }

    public String[] getCiphersuites() {
        return this.ciphersuites;
    }

    public void setCiphersuites(String[] ciphersuites) {
        this.ciphersuites = ciphersuites;
    }
    
}
