package srsc.sadkdp;

import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyStore;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import com.google.gson.Gson;

import srsc.Utils;
import srsc.sadkdp.jsonEntities.*;

public class SADKDP {

    private static final int HEADERSIZE = Byte.SIZE / 8 + Integer.SIZE / 8;

    private static final byte VERSION = 0b00100000;
    private static final byte MESSAGE_1 = 0b00000001;
    private static final byte MESSAGE_2 = 0b00000010;
    private static final byte MESSAGE_3 = 0b00000011;
    private static final byte MESSAGE_4 = 0b00000100;
    private static final byte MESSAGE_5 = 0b00000101;
    private static final byte MESSAGE_6 = 0b00000110;

    Gson gson;
    KeyStore ks;

    public SADKDP(String pathToKeyStore, String keyStorePassword) throws Exception{
        this.gson = new Gson();
        this.ks = KeyStore.getInstance(new File(pathToKeyStore), keyStorePassword.toCharArray()); // TODO a password e pa entrar aqui?
    }
    
    public byte[] encodeMessage1(String UserID, String ProxyBoxId){

        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_1);

        Hello content = new Hello(UserID, ProxyBoxId);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        return ByteBuffer.allocate(HEADERSIZE+payloadSize).put(versionPlusMsgType).putInt(payloadSize).put(payload).array();
    }

    public Hello decodeMessage1(byte[] data) throws Exception {

        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 &  versionPlusMsgType);

        if(version!=VERSION || messageType!=MESSAGE_1)
            throw new Exception();

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        String message = Utils.toString(payload);
        Hello returnObj = gson.fromJson(message, Hello.class);

        return returnObj;
    }

    public byte[] encodeMessage2(int N1, byte[] Salt, int Counter) {
        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_2);

        AuthenticationRequest content = new AuthenticationRequest(N1, Salt, Counter);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        return ByteBuffer.allocate(HEADERSIZE+payloadSize).put(versionPlusMsgType).putInt(payloadSize).put(payload).array();
    }

    public AuthenticationRequest decodeMessage2(byte[] data) throws Exception{
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 &  versionPlusMsgType);

        if(version!=VERSION || messageType!=MESSAGE_2)
            throw new Exception();

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        String message = Utils.toString(payload);
        AuthenticationRequest returnObj = gson.fromJson(message, AuthenticationRequest.class);

        return returnObj;
    }

    public byte[] encodeMessage3(String password, byte[] salt, int counter, int n1_ /*n1+1*/, int n2, String movieId) throws Exception {
        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_3);

        Authentication content = new Authentication(n1_, n2, movieId);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        //int payloadSize = payload.length;

        //PBE
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory
				.getInstance("PBEWithMD5AndTripleDES");
                
        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, counter);
        Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");

		cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
        byte[] encryptedPayload = cipher.doFinal(payload);
        int encryptedPayloadSize = encryptedPayload.length;

        //Integrity check
        MessageDigest hash = MessageDigest.getInstance("SHA256", "BC");
        hash.update(Utils.toByteArray(n1_));
        byte[] integrityCheck = hash.digest();
        int intCheckSize = hash.getDigestLength();

        return ByteBuffer.allocate(HEADERSIZE+encryptedPayloadSize+intCheckSize).put(versionPlusMsgType).putInt(encryptedPayloadSize).put(encryptedPayload).put(integrityCheck).array();
    }

    public Authentication decodeMessage3(String password, byte[] salt, int counter, byte[] data, int myLastNounce) throws Exception {
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 &  versionPlusMsgType);

        int encryptedpPayloadSize = dataBuff.getInt();
        byte[] encryptedPayload = new byte[encryptedpPayloadSize];
        dataBuff.get(encryptedPayload);
        byte[] integrityCheck = new byte[data.length-HEADERSIZE-encryptedpPayloadSize];
        dataBuff.get(integrityCheck);

        if(version!=VERSION || messageType!=MESSAGE_3)
            throw new Exception();

        MessageDigest hash = MessageDigest.getInstance("SHA256", "BC");
        hash.update(Utils.toByteArray(myLastNounce+1));
        if(!MessageDigest.isEqual(hash.digest(), integrityCheck)){
                throw new Exception();
        }

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
		SecretKeyFactory secretKeyFactory = SecretKeyFactory
				.getInstance("PBEWithMD5AndTripleDES");
		SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, counter);

		Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
		cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
        byte[] output = cipher.doFinal(encryptedPayload);

        String message = Utils.toString(output);
        Authentication returnObj = gson.fromJson(message, Authentication.class);

        return returnObj;
    }

    public byte[] encodeMessage4(int price, int n2_, int n3) {
        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_4);

        PaymentRequest content = new PaymentRequest(price, n2_, n3);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);

        KeyStore ks = KeyStore.getInstance("pcks12");
        

        return null;
    }

    public PaymentRequest decodeMessage4(byte[] data, int myLastNounce) {
        return null;
    }

    public byte[] encodeMessage5(int n3_, int n4, String paymentCoin) {
        return null;
    }

    public Payment decodeMessage5(byte[] data, int myLastNounce) {
        return null;
    }

    public byte[] encodeMessage6() {
        return null;
    }

    public TicketCredentials decodeMessage6() {
        return null;
    }


    
}
