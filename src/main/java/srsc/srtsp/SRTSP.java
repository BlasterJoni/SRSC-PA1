package srsc.srtsp;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.HashSet;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import com.google.gson.Gson;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import srsc.Utils;
import srsc.sadkdp.jsonEntities.TicketCredentialsReturn;
import srsc.srtsp.jsonEntities.*;

public class SRTSP {

    private static final int HEADERSIZE = Byte.SIZE / 8 + Byte.SIZE / 8 + Integer.SIZE / 8;

    private static final byte VERSION = 0b00000011;
    private static final byte MESSAGE_1 = 0b00000001;
    private static final byte MESSAGE_2 = 0b00000010;
    private static final byte MESSAGE_3 = 0b00000011;
    private static final byte MESSAGE_4 = 0b00000100;

    Gson gson;
    KeyStore ks;
    String keyStorePassword;
    Set<Integer> nounces;

    ServerSocket serverSocket;
    Socket clientSocket;
    BufferedWriter out;
    BufferedReader in;
    int ackPaPrimeiraFrame;

    public SRTSP(String pathToKeyStore, String keyStorePassword) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        this.gson = new Gson();
        this.ks = KeyStore.getInstance(new File(pathToKeyStore), keyStorePassword.toCharArray()); // TODO a password e
                                                                                                  // pa entrar aqui?
        this.keyStorePassword = keyStorePassword;
        this.nounces = new HashSet<>();
    }

    public TicketCredentials startReceiveTicket(int port) throws Exception {

        serverSocket = new ServerSocket(port);

        clientSocket = serverSocket.accept();
        out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        String message;
        int myLastNounce;
        TicketCredentials tc;

        message = in.readLine();
        RequestAndCredentials requestAndCredentials = decodeMessage1(message);
        tc = requestAndCredentials.getTicketCredentials();

        addSeenNounce(tc.getN4_()); //check NC1

        myLastNounce = newNounce();
        String verification = encodeMessage2(tc.getSessionKey(), tc.getSessionIV(), tc.getMacKey(), requestAndCredentials.getN1()+1, myLastNounce, true);
        out.write(verification);
        out.newLine();
        out.flush();

        message = in.readLine();
        AckVerification ackVerification = decodeMessage3(tc.getSessionKey(), tc.getSessionIV(), tc.getMacKey(), message, myLastNounce);
        if (ackVerification.getN2_() != myLastNounce + 1)
            throw new Exception();

        addSeenNounce(ackVerification.getN2_());

        ackPaPrimeiraFrame = ackVerification.getN3()+1;

        return tc;
    }

    public InetSocketAddress getClientAddress(){
        return new InetSocketAddress(clientSocket.getInetAddress(), 9999);
    }

    public void sendFirstFrame(byte[] frame, int size, TicketCredentials tc) throws Exception{
        byte[] frameCropped =  new byte[size];
        System.arraycopy(frame, 0, frameCropped, 0, size);

        String SyncInitialFrame = encodeMessage4(tc.getSessionKey(), tc.getSessionIV(), tc.getMacKey(), frameCropped, ackPaPrimeiraFrame);
        out.write(SyncInitialFrame);
        out.newLine();
        out.flush();   

        out.close();
        in.close();
        clientSocket.close();
        serverSocket.close();
    }

    public byte[] requestMovie(TicketCredentialsReturn ticketCredentials) throws Exception {
        clientSocket = new Socket(ticketCredentials.getIp(), Integer.parseInt(ticketCredentials.getPort()));
        out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
        in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        String message;
        int myLastNounce;

        myLastNounce = newNounce();
        String requestAndCredentials = encodeMessage1(ticketCredentials.getStreamTicket(), ticketCredentials.getStreamSigBytes(), myLastNounce);
        out.write(requestAndCredentials);
        out.newLine();
        out.flush();

        message = in.readLine();
        Verification verification = decodeMessage2(ticketCredentials.getSessionKey(), ticketCredentials.getSessionIV(), ticketCredentials.getMacKey(), message, myLastNounce);
        if(verification.getN1_()!=myLastNounce+1 || !verification.getTicketValidityConfirmation())
            throw new Exception();

        addSeenNounce(verification.getN1_());

        myLastNounce = newNounce();
        String ackVerification = encodeMessage3(ticketCredentials.getSessionKey(), ticketCredentials.getSessionIV(), ticketCredentials.getMacKey(), verification.getN2()+1, myLastNounce);
        out.write(ackVerification);
        out.newLine();
        out.flush();

        message = in.readLine();
        SyncInitialFrame syncInitialFrame = decodeMessage4(ticketCredentials.getSessionKey(), ticketCredentials.getSessionIV(), ticketCredentials.getMacKey(), message, myLastNounce);
        if(syncInitialFrame.getN3_()!=myLastNounce+1)
            throw new Exception();

        addSeenNounce(syncInitialFrame.getN3_());

        clientSocket.close();

        return syncInitialFrame.getframe();
    }

        private String encodeMessage1(byte[] ticket, byte[] signature, int n1) {
        RequestAndCredentialsSend content = new RequestAndCredentialsSend(ticket, signature, n1);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + payloadSize).put(VERSION).put(MESSAGE_1).putInt(payloadSize)
                .put(payload).array();

        System.out.println("Msg1 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private RequestAndCredentials decodeMessage1(String dataString) throws Exception {

        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg1 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

        if (version != VERSION || messageType != MESSAGE_1)
            throw new Exception();

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        String message = Utils.toString(payload);
        RequestAndCredentialsSend obj = gson.fromJson(message, RequestAndCredentialsSend.class);

        Signature signature = Signature.getInstance("SHA512withECDSA", "BC");
        signature.initVerify(ks.getCertificate("signalingserver").getPublicKey());
        signature.update(obj.getTicketCredentials());
        if (!signature.verify(obj.getSignature()))
            throw new Exception();

        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, ks.getKey("streamingserver", keyStorePassword.toCharArray()));
        byte[] output = cipher.doFinal(obj.getTicketCredentials());
        String messageTPB = Utils.toString(output);
        TicketCredentials tpbObj = gson.fromJson(messageTPB, TicketCredentials.class);

        return new RequestAndCredentials(tpbObj, obj.getN1());
    }

    private String encodeMessage2(byte[] sessionKey, byte[] ivBytes, byte[] macKey, int n1_, int n2,
            boolean TickeyValidityConfirmation) throws Exception {

        Verification content = new Verification(n1_, n2, TickeyValidityConfirmation);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);

        // Encrypt
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Key secretKey = new SecretKeySpec(sessionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedPayload = cipher.doFinal(payload);
        int encryptedPayloadSize = encryptedPayload.length;

        // Integrity check
        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(macKey, "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(n1_));
        byte[] integrityCheck = hMac.doFinal();
        int intCheckSize = hMac.getMacLength();

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + encryptedPayloadSize + intCheckSize).put(VERSION).put(MESSAGE_2)
                .putInt(encryptedPayloadSize).put(encryptedPayload).put(integrityCheck).array();

        System.out.println("Msg2 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private Verification decodeMessage2(byte[] sessionKey, byte[] ivBytes, byte[] macKey, String dataString,
            int myLastNounce) throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg2 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

        if (version != VERSION || messageType != MESSAGE_2)
            throw new Exception();

        int encryptedPayloadSize = dataBuff.getInt();
        byte[] encryptedPayload = new byte[encryptedPayloadSize];
        dataBuff.get(encryptedPayload);
        byte[] integrityCheck = new byte[data.length - HEADERSIZE - encryptedPayloadSize];
        dataBuff.get(integrityCheck);

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(macKey, "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(myLastNounce + 1));
        if (!MessageDigest.isEqual(hMac.doFinal(), integrityCheck)) {
            throw new Exception();
        }

        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Key secretKey = new SecretKeySpec(sessionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] payload = cipher.doFinal(encryptedPayload);

        String message = Utils.toString(payload);
        Verification toRet = gson.fromJson(message, Verification.class);

        return toRet;
    }

    private String encodeMessage3(byte[] sessionKey, byte[] ivBytes, byte[] macKey, int n2_, int n3) throws Exception {
        AckVerification content = new AckVerification(n2_, n3);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);

        // Encrypt
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Key secretKey = new SecretKeySpec(sessionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedPayload = cipher.doFinal(payload);
        int encryptedPayloadSize = encryptedPayload.length;

        // Integrity check
        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(macKey, "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(n2_));
        byte[] integrityCheck = hMac.doFinal();
        int intCheckSize = hMac.getMacLength();

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + encryptedPayloadSize + intCheckSize).put(VERSION).put(MESSAGE_3)
                .putInt(encryptedPayloadSize).put(encryptedPayload).put(integrityCheck).array();

        System.out.println("Msg3 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private AckVerification decodeMessage3(byte[] sessionKey, byte[] ivBytes, byte[] macKey, String dataString,
            int myLastNounce) throws Exception {

        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg3 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

        if (version != VERSION || messageType != MESSAGE_3)
            throw new Exception();

        int encryptedPayloadSize = dataBuff.getInt();
        byte[] encryptedPayload = new byte[encryptedPayloadSize];
        dataBuff.get(encryptedPayload);
        byte[] integrityCheck = new byte[data.length - HEADERSIZE - encryptedPayloadSize];
        dataBuff.get(integrityCheck);

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(macKey, "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(myLastNounce + 1));
        if (!MessageDigest.isEqual(hMac.doFinal(), integrityCheck)) {
            throw new Exception();
        }

        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Key secretKey = new SecretKeySpec(sessionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] payload = cipher.doFinal(encryptedPayload);

        String message = Utils.toString(payload);
        AckVerification toRet = gson.fromJson(message, AckVerification.class);

        return toRet;
    }

    private String encodeMessage4(byte[] sessionKey, byte[] ivBytes, byte[] macKey, byte[] frame, int n3_)
            throws Exception {
        SyncInitialFrame content = new SyncInitialFrame(n3_, frame);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);

        // Encrypt
        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Key secretKey = new SecretKeySpec(sessionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivSpec);
        byte[] encryptedPayload = cipher.doFinal(payload);
        int encryptedPayloadSize = encryptedPayload.length;

        // Integrity check
        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(macKey, "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(n3_));
        byte[] integrityCheck = hMac.doFinal();
        int intCheckSize = hMac.getMacLength();

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + encryptedPayloadSize + intCheckSize).put(VERSION).put(MESSAGE_4)
                .putInt(encryptedPayloadSize).put(encryptedPayload).put(integrityCheck).array();

        System.out.println("Msg4 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private SyncInitialFrame decodeMessage4(byte[] sessionKey, byte[] ivBytes, byte[] macKey, String dataString,
            int myLastNounce) throws Exception {

        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg4 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

        if (version != VERSION || messageType != MESSAGE_4)
            throw new Exception();

        int encryptedPayloadSize = dataBuff.getInt();
        byte[] encryptedPayload = new byte[encryptedPayloadSize];
        dataBuff.get(encryptedPayload);
        byte[] integrityCheck = new byte[data.length - HEADERSIZE - encryptedPayloadSize];
        dataBuff.get(integrityCheck);

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(macKey, "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(myLastNounce + 1));
        if (!MessageDigest.isEqual(hMac.doFinal(), integrityCheck)) {
            throw new Exception();
        }

        IvParameterSpec ivSpec = new IvParameterSpec(ivBytes);
        Key secretKey = new SecretKeySpec(sessionKey, "AES");
        Cipher cipher = Cipher.getInstance("AES/CTR/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, ivSpec);
        byte[] payload = cipher.doFinal(encryptedPayload);

        String message = Utils.toString(payload);
        SyncInitialFrame toRet = gson.fromJson(message, SyncInitialFrame.class);

        return toRet;
    }


    private int newNounce() {
        int random;
        do {
            random = new SecureRandom().nextInt();
        } while (nounces.contains(random+1));

        return random;
    }

    private void addSeenNounce(int nounce) throws Exception{
        if(!nounces.contains(nounce))
            nounces.add(nounce);
        else
            throw new Exception();
    }

}
