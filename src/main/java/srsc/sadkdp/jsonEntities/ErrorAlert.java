package srsc.sadkdp.jsonEntities;

public class ErrorAlert {
    private byte mType;
    private String errorCode;

    public ErrorAlert(){
    }

    public ErrorAlert(byte mType, String errorCode) {
        this.mType = mType;
        this.errorCode = errorCode;
    }

    public byte getMType() {
        return this.mType;
    }

    public void setMType(byte mType) {
        this.mType = mType;
    }

    public String getErrorCode() {
        return this.errorCode;
    }

    public void setErrorCode(String errorCode) {
        this.errorCode = errorCode;
    }

}