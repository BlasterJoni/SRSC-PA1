package srsc.srtsp;

import srsc.cryptoconfiguration.Confidentiality;
import srsc.cryptoconfiguration.Integrity;

import java.net.*;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;



public class SimplfiedSRTSPDatagramSocket extends DatagramSocket {
    private Confidentiality confidentiality;
    private Integrity integrity;

    public SimplfiedSRTSPDatagramSocket(Confidentiality confidentiality, Integrity integrity) throws SocketException {
        super();
        this.confidentiality = confidentiality;
        this.integrity = integrity;
    }
    
    @Override
    public void send(DatagramPacket p){

        //add version
        byte version = 0b00010000;

        //add message type
        byte message = 0b00000000;

        //add payload size

        //add payload + mac

/*
        byte[] cipherText = new byte[cipher.getOutputSize(input.length() + hMac.getMacLength())];

        int ctLength = cipher.update(Utils.toByteArray(input), 0, input.length(), cipherText, 0);
         
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(input));
          
        ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);
*/
        

    }

    @Override
    public void receive(DatagramPacket p){

    }
}
