package srsc.srtsp.jsonEntities;

public class SyncInitialFrame {
    private int n3_;
    private byte[] frame;

    public SyncInitialFrame() {
    }

    public SyncInitialFrame(int n3_, byte[] frame) {
        this.n3_ = n3_;
        this.frame = frame;
    }

    public int getN3_() {
        return this.n3_;
    }

    public void setN3_(int n3_) {
        this.n3_ = n3_;
    }

    public byte[] getframe() {
        return this.frame;
    }

    public void setframe(byte[] frame) {
        this.frame = frame;
    }
}