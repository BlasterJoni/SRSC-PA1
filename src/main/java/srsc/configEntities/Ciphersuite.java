package srsc.configEntities;

public class Ciphersuite {
    Confidentiality confidentiality;
    Integrity integrity;

    public Ciphersuite(){
    }

    public Ciphersuite(Confidentiality confidentiality, Integrity integrity){
        this.confidentiality = confidentiality;
        this.integrity = integrity;
    }

    public Confidentiality getConfidentiality() {
        return this.confidentiality;
    }

    public void setConfidentiality(Confidentiality confidentiality) {
        this.confidentiality = confidentiality;
    }

    public Integrity getIntegrity() {
        return this.integrity;
    }

    public void setIntegrity(Integrity integrity) {
        this.integrity = integrity;
    }
    
}
