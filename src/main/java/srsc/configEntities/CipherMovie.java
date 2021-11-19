package srsc.configEntities;

public class CipherMovie {
    private String movie;
    private int ppvprice;
    private Ciphersuite ciphersuite;

    public CipherMovie(){
    }

    public CipherMovie(String movie, int ppvprice, Ciphersuite ciphersuite) {
        this.movie = movie;
        this.ppvprice = ppvprice;
        this.ciphersuite = ciphersuite;
    }

    public String getMovie() {
        return this.movie;
    }

    public void setMovie(String movie) {
        this.movie = movie;
    }

    public int getPpvprice() {
        return this.ppvprice;
    }

    public void setPpvprice(int ppvprice) {
        this.ppvprice = ppvprice;
    }

    public Ciphersuite getCiphersuite() {
        return this.ciphersuite;
    }

    public void setCiphersuite(Ciphersuite ciphersuite) {
        this.ciphersuite = ciphersuite;
    }
    
    
}
