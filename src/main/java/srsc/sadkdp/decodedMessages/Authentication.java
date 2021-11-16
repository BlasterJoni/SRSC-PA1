package srsc.sadkdp.decodedMessages;

public class Authentication {
    private String n1_, n2, movieId, integrityCheck3;

    public Authentication(String n1_, String n2, String movieId, String integrityCheck3) {
        this.n1_ = n1_;
        this.n2 = n2;
        this.movieId = movieId;
        this.integrityCheck3 = integrityCheck3;
    }

    public String getN1_() {
        return this.n1_;
    }

    public void setN1_(String n1_) {
        this.n1_ = n1_;
    }

    public String getN2() {
        return this.n2;
    }

    public void setN2(String n2) {
        this.n2 = n2;
    }

    public String getMovieId() {
        return this.movieId;
    }

    public void setMovieId(String movieId) {
        this.movieId = movieId;
    }

    public String getIntegrityCheck3() {
        return this.integrityCheck3;
    }

    public void setIntegrityCheck3(String integrityCheck3) {
        this.integrityCheck3 = integrityCheck3;
    }

}