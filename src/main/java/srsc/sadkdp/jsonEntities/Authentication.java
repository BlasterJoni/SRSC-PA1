package srsc.sadkdp.jsonEntities;

public class Authentication {
    private String movieId;
    private int n1_, n2;

    public Authentication() {
    }

    public Authentication(int n1_, int n2, String movieId) {
        this.n1_ = n1_;
        this.n2 = n2;
        this.movieId = movieId;
    }

    public int getN1_() {
        return this.n1_;
    }

    public void setN1_(int n1_) {
        this.n1_ = n1_;
    }

    public int getN2() {
        return this.n2;
    }

    public void setN2(int n2) {
        this.n2 = n2;
    }

    public String getMovieId() {
        return this.movieId;
    }

    public void setMovieId(String movieId) {
        this.movieId = movieId;
    }

}