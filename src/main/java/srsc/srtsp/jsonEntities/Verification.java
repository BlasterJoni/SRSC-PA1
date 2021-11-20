package srsc.srtsp.jsonEntities;

public class Verification {
    private int n1_, n2;
    private boolean ticketValidityConfirmation;

    public Verification() {
    }

    public Verification(int n1__, int n2, boolean ticketValidityConfirmation) {
        this.n1_ = n1__;
        this.n2 = n2;
        this.ticketValidityConfirmation = ticketValidityConfirmation;
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

    public boolean getTicketValidityConfirmation() {
        return this.ticketValidityConfirmation;
    }

    public void setTicketValidityConfirmation(boolean ticketValidityConfirmation) {
        this.ticketValidityConfirmation = ticketValidityConfirmation;
    }
}