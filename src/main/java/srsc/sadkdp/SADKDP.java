package srsc.sadkdp;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.*;
import java.util.*;

import java.lang.reflect.Type;
import com.google.gson.reflect.TypeToken;
import com.google.gson.Gson;

import org.bouncycastle.jcajce.provider.symmetric.Grain128.KeyGen;
import org.bouncycastle.jcajce.provider.symmetric.util.PBE.Util;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import srsc.Utils;
import srsc.configEntities.*;
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
    String keyStorePassword;
    Set<Integer> nounces;

    public SADKDP(String pathToKeyStore, String keyStorePassword) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        this.gson = new Gson();
        this.ks = KeyStore.getInstance(new File(pathToKeyStore), keyStorePassword.toCharArray()); // TODO a password e
                                                                                                  // pa entrar aqui?
        this.keyStorePassword = keyStorePassword;
        this.nounces = new HashSet<>();
    }

    public String encodeMessage1(String UserID, String ProxyBoxId) {

        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_1);

        Hello content = new Hello(UserID, ProxyBoxId);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + payloadSize).put(versionPlusMsgType).putInt(payloadSize)
                .put(payload).array();

        System.out.println("Msg1 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    public Hello decodeMessage1(String dataString) throws Exception {

        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg1 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 & versionPlusMsgType);

        if (version != VERSION || messageType != MESSAGE_1)
            throw new Exception();

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        String message = Utils.toString(payload);
        Hello returnObj = gson.fromJson(message, Hello.class);

        return returnObj;
    }

    public String encodeMessage2(int N1, byte[] Salt, int Counter) {
        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_2);

        AuthenticationRequest content = new AuthenticationRequest(N1, Salt, Counter);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + payloadSize).put(versionPlusMsgType).putInt(payloadSize)
                .put(payload).array();

        System.out.println("Msg2 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    public AuthenticationRequest decodeMessage2(String dataString) throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg2 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 & versionPlusMsgType);

        if (version != VERSION || messageType != MESSAGE_2)
            throw new Exception();

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        String message = Utils.toString(payload);
        AuthenticationRequest returnObj = gson.fromJson(message, AuthenticationRequest.class);

        return returnObj;
    }

    public String encodeMessage3(String password, byte[] salt, int counter, int n1_ /* n1+1 */, int n2, String movieId)
            throws Exception {
        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_3);

        Authentication content = new Authentication(n1_, n2, movieId);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        // int payloadSize = payload.length;

        // PBE
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");

        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);
        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, counter);
        Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey, pbeParameterSpec);
        byte[] encryptedPayload = cipher.doFinal(payload);
        int encryptedPayloadSize = encryptedPayload.length;

        // Integrity check
        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        int intCheckSize = hMac.getMacLength();
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(n1_));
        byte[] integrityCheck = hMac.doFinal();

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + encryptedPayloadSize + intCheckSize).put(versionPlusMsgType)
                .putInt(encryptedPayloadSize).put(encryptedPayload).put(integrityCheck).array();

        System.out.println("Msg3 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    public Authentication decodeMessage3(String password, byte[] salt, int counter, String dataString, int myLastNounce)
            throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg3 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 & versionPlusMsgType);

        int encryptedPayloadSize = dataBuff.getInt();
        byte[] encryptedPayload = new byte[encryptedPayloadSize];
        dataBuff.get(encryptedPayload);
        byte[] integrityCheck = new byte[data.length - HEADERSIZE - encryptedPayloadSize];
        dataBuff.get(integrityCheck);

        if (version != VERSION || messageType != MESSAGE_3)
            throw new Exception();

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(myLastNounce+1));
        if (!MessageDigest.isEqual(hMac.doFinal(), integrityCheck)) {
            throw new Exception();
        }

        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithMD5AndTripleDES");
        SecretKey secretKey = secretKeyFactory.generateSecret(pbeKeySpec);

        PBEParameterSpec pbeParameterSpec = new PBEParameterSpec(salt, counter);

        Cipher cipher = Cipher.getInstance("PBEWithMD5AndTripleDES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey, pbeParameterSpec);
        byte[] output = cipher.doFinal(encryptedPayload);

        String message = Utils.toString(output);
        Authentication returnObj = gson.fromJson(message, Authentication.class);

        return returnObj;
    }

    public String encodeMessage4(String password, int price, int n2_, int n3) throws Exception {
        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_4);

        PaymentRequest content = new PaymentRequest(price, n2_, n3);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);

        Signature signature = Signature.getInstance("SHA512withECDSA", "BC");
        signature.initSign((PrivateKey) ks.getKey("signalingserver", keyStorePassword.toCharArray()));
        signature.update(payload);
        byte[] sigBytes = signature.sign();

        SignatureEnvelope sigEnv = new SignatureEnvelope(payload, sigBytes);
        String sigEnvMessage = gson.toJson(sigEnv);
        byte[] sigEnvPayload = Utils.toByteArray(sigEnvMessage);
        int sigEnvPayloadSize = sigEnvPayload.length;

        // Integrity check
        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        int intCheckSize = hMac.getMacLength();
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(n2_));
        byte[] integrityCheck = hMac.doFinal();

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + sigEnvPayloadSize + intCheckSize).put(versionPlusMsgType)
                .putInt(sigEnvPayloadSize).put(sigEnvPayload).put(integrityCheck).array();

        System.out.println("Msg4 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    public PaymentRequest decodeMessage4(String password, String dataString, int myLastNounce) throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg4 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 & versionPlusMsgType);

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        byte[] integrityCheck = new byte[data.length - HEADERSIZE - payloadSize];
        dataBuff.get(integrityCheck);

        if (version != VERSION || messageType != MESSAGE_4)
            throw new Exception();

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(myLastNounce+1));
        if (!MessageDigest.isEqual(hMac.doFinal(), integrityCheck)) {
            throw new Exception();
        }

        SignatureEnvelope sigEnv = gson.fromJson(Utils.toString(payload), SignatureEnvelope.class);
        Signature signature = Signature.getInstance("SHA512withECDSA", "BC");
        signature.initVerify(ks.getCertificate("signalingserver").getPublicKey());
        signature.update(sigEnv.getPayload());
        if (!signature.verify(sigEnv.getSigBytes())) {
            throw new Exception();
        }

        String message = Utils.toString(sigEnv.getPayload());
        PaymentRequest returnObj = gson.fromJson(message, PaymentRequest.class);

        return returnObj;
    }

    public String encodeMessage5(String password, int n3_, int n4, String paymentCoin) throws Exception {
        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_5);

        Payment content = new Payment(n3_, n4, paymentCoin);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);

        Signature signature = Signature.getInstance("SHA512withECDSA", "BC");
        signature.initSign((PrivateKey) ks.getKey("proxybox", keyStorePassword.toCharArray()));
        signature.update(payload);
        byte[] sigBytes = signature.sign();

        SignatureEnvelope sigEnv = new SignatureEnvelope(payload, sigBytes);
        String sigEnvMessage = gson.toJson(sigEnv);
        byte[] sigEnvPayload = Utils.toByteArray(sigEnvMessage);
        int sigEnvPayloadSize = sigEnvPayload.length;

        // Integrity check
        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        int intCheckSize = hMac.getMacLength();
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(n3_));
        byte[] integrityCheck = hMac.doFinal();

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + sigEnvPayloadSize + intCheckSize).put(versionPlusMsgType)
                .putInt(sigEnvPayloadSize).put(sigEnvPayload).put(integrityCheck).array();

        System.out.println("Msg5 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    public Payment decodeMessage5(String password, String dataString, int myLastNounce) throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg5 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 & versionPlusMsgType);

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        byte[] integrityCheck = new byte[data.length - HEADERSIZE - payloadSize];
        dataBuff.get(integrityCheck);

        if (version != VERSION || messageType != MESSAGE_5)
            throw new Exception();

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(myLastNounce+1));
        if (!MessageDigest.isEqual(hMac.doFinal(), integrityCheck)) {
            throw new Exception();
        }

        SignatureEnvelope sigEnv = gson.fromJson(Utils.toString(payload), SignatureEnvelope.class);
        Signature signature = Signature.getInstance("SHA512withECDSA", "BC");
        signature.initVerify(ks.getCertificate("proxybox").getPublicKey());
        signature.update(sigEnv.getPayload());
        if (!signature.verify(sigEnv.getSigBytes())) {
            throw new Exception();
        }

        String message = Utils.toString(sigEnv.getPayload());
        Payment returnObj = gson.fromJson(message, Payment.class);

        return returnObj;
    }

    public String encodeMessage6(String password, String ip, String port, String movieId, Ciphersuite ciphersuitConf, byte[] sessionKey, byte[] sessionIV, byte[] macKey,
            int n4_, int nc1) throws Exception {
        byte versionPlusMsgType = (byte) (VERSION | MESSAGE_6);

        TicketCredentials content1 = new TicketCredentials(ip, port, movieId, ciphersuitConf, sessionKey, sessionIV, macKey, n4_);
        String message1 = gson.toJson(content1);
        byte[] payload1 = Utils.toByteArray(message1);

        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, ks.getCertificate("proxybox").getPublicKey());
        byte[] encryptedPayload1 = cipher.doFinal(payload1);
        int encryptedPayloadSize1 = encryptedPayload1.length;
        
        Signature signature1 = Signature.getInstance("SHA512withECDSA", "BC");
        signature1.initSign((PrivateKey) ks.getKey("signalingserver", keyStorePassword.toCharArray()));
        // signature.initSign(((PrivateKeyEntry) ks.getEntry("signalingserver", new
        // PasswordProtection(keyStorePassword.toCharArray()))).getPrivateKey());
        signature1.update(encryptedPayload1);
        byte[] sigBytes1 = signature1.sign();

        TicketCredentials content2 = new TicketCredentials(ip, port, movieId, ciphersuitConf, sessionKey, sessionIV, macKey, nc1);
        String message2 = gson.toJson(content2);
        byte[] payload2 = Utils.toByteArray(message2);

        // cipher=Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.ENCRYPT_MODE, ks.getCertificate("streamingserver").getPublicKey());
        byte[] encryptedPayload2 = cipher.doFinal(payload2);
        int encryptedPayloadSize2 = encryptedPayload2.length;

        Signature signature2 = Signature.getInstance("SHA512withECDSA", "BC");
        signature2.initSign((PrivateKey) ks.getKey("signalingserver", keyStorePassword.toCharArray()));
        // signature.initSign(((PrivateKeyEntry) ks.getEntry("signalingserver", new
        // PasswordProtection(keyStorePassword.toCharArray()))).getPrivateKey());
        signature2.update(encryptedPayload2);
        byte[] sigBytes2 = signature2.sign();

        TicketCredentialsMessage content = new TicketCredentialsMessage(encryptedPayload1, encryptedPayload2, sigBytes1, sigBytes2);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        // Integrity check
        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        int intCheckSize = hMac.getMacLength();
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(n4_));
        byte[] integrityCheck = hMac.doFinal();

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + payloadSize + intCheckSize).put(versionPlusMsgType)
                .putInt(payloadSize).put(payload).put(integrityCheck).array();

        System.out.println("Msg6 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    public TicketCredentialsReturn decodeMessage6(String password, String dataString, int myLastNounce) throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg6 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 & versionPlusMsgType);

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        byte[] integrityCheck = new byte[data.length - HEADERSIZE - payloadSize];
        dataBuff.get(integrityCheck);

        if (version != VERSION || messageType != MESSAGE_6)
            throw new Exception();

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(myLastNounce+1));
        if (!MessageDigest.isEqual(hMac.doFinal(), integrityCheck)) {
            throw new Exception();
        }

        String message = Utils.toString(payload);
        TicketCredentialsMessage tcm = gson.fromJson(message, TicketCredentialsMessage.class);
        byte[] tpb = tcm.getTicketForProxyBox();
        byte[] tss = tcm.getTicketForStreamingServer();

        Signature signature1 = Signature.getInstance("SHA512withECDSA", "BC");
        signature1.initVerify(ks.getCertificate("signalingserver").getPublicKey());
        signature1.update(tpb);
        if (!signature1.verify(tcm.getSignatureProxyBox()))
            throw new Exception();

        Signature signature2 = Signature.getInstance("SHA512withECDSA", "BC");
        signature2.initVerify(ks.getCertificate("signalingserver").getPublicKey());
        signature2.update(tss);
        if (!signature2.verify(tcm.getSignatureStreamingServer()))
            throw new Exception();

        Cipher cipher = Cipher.getInstance("ECIES", "BC");
        cipher.init(Cipher.DECRYPT_MODE, ks.getKey("proxybox", keyStorePassword.toCharArray()));
        byte[] output = cipher.doFinal(tcm.getTicketForProxyBox());
        String messageTPB = Utils.toString(output);
        TicketCredentials tpbObj = gson.fromJson(messageTPB, TicketCredentials.class);

        return new TicketCredentialsReturn(tpbObj.getIp(), tpbObj.getPort(), tpbObj.getMovieId(),
                tpbObj.getCiphersuiteConf(), tpbObj.getSessionKey(), tpbObj.getSessionIV(), tpbObj.getMacKey(), tpbObj.getN4_(),
                tcm.getTicketForStreamingServer(), tcm.getSignatureStreamingServer());
    }

    public String encodeError(String password, byte messageType, String errorCode) throws Exception {

        byte versionPlusMsgType = (byte) (VERSION | messageType);

        ErrorAlert errorAlert = new ErrorAlert(messageType, errorCode);
        String message = gson.toJson(errorAlert);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        int intCheckSize = hMac.getMacLength();
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(errorAlert.toString()));
        byte[] integrityCheck = hMac.doFinal();

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + payloadSize + intCheckSize).put(versionPlusMsgType)
                .putInt(payloadSize).put(payload).put(integrityCheck).array();

        System.out.println("Error message sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    public void decodeError(String password, String dataString) throws Exception {

        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte versionPlusMsgType = dataBuff.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 & versionPlusMsgType);

        if (version != VERSION || (messageType != MESSAGE_90 && messageType != MESSAGE_91))
            return;

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        byte[] integrityCheck = new byte[data.length - HEADERSIZE - payloadSize];
        dataBuff.get(integrityCheck);

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(dataString));
        if (!MessageDigest.isEqual(hMac.doFinal(), integrityCheck)) {
            throw new Exception();
        }
        
    }

    public void startServer(int port, String pathToUserProxiesJSON, String pathToCipherMoviesJSON) throws Exception {

        Map<String, UserProxy> users = getUsers(pathToUserProxiesJSON);
        Map<String, CipherMovie> movies = getMovies(pathToCipherMoviesJSON);

        ServerSocket serverSocket = new ServerSocket(port);

        Socket clientSocket = serverSocket.accept();
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        String message;
        int myLastNounce;
        int counter = 1;

        message = in.readLine();
        Hello hello = decodeMessage1(message);
        if (!users.containsKey(hello.getUserId())
                || !users.get(hello.getUserId()).getProxyId().equals(hello.getProxyBoxId())) {
            throw new Exception();
        }

        myLastNounce = newNounce();
        byte[] Salt = new byte[8];
        new SecureRandom().nextBytes(Salt);
        String authenticationrequest = encodeMessage2(myLastNounce, Salt, counter);
        out.write(authenticationrequest);
        out.newLine();
        out.flush();

        message = in.readLine();
        String password = users.get(hello.getUserId()).getPassword();
        Authentication authentication = decodeMessage3(password, Salt, counter++,
                message, myLastNounce);
        if (authentication.getN1_() != myLastNounce + 1 || !movies.containsKey(authentication.getMovieId()))
            throw new Exception();
        CipherMovie movie = movies.get(authentication.getMovieId());

        myLastNounce = newNounce();
        String paymentrequest = encodeMessage4(password, movie.getPpvprice(), authentication.getN2() + 1, myLastNounce);
        out.write(paymentrequest);
        out.newLine();
        out.flush();

        message = in.readLine();
        Payment payment = decodeMessage5(password, message, myLastNounce);
        if (payment.getN3_() != myLastNounce + 1) // TODO verificar se a coin é legit
            throw new Exception();

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(256);
        SecretKey sessionKey = kg.generateKey();
        SecretKey macKey = kg.generateKey();

        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);

        String ticketcredentials = encodeMessage6(password, "localhost", "42169", movie.getMovie(), movie.getCiphersuite(),
                sessionKey.getEncoded(), iv, macKey.getEncoded(), payment.getN4() + 1, 0);
        out.write(ticketcredentials);
        out.newLine();
        out.flush();

        out.close();
        in.close();
        clientSocket.close();
        serverSocket.close();
        
    }

    public TicketCredentialsReturn getTicket(String ip, String port, String username, String password, String proxyId,
            String movieId) throws Exception {
        Socket clientSocket = new Socket(ip, Integer.parseInt(port));
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        String message;
        int myLastNounce;

        String hello = encodeMessage1(username, proxyId);
        out.write(hello);
        out.newLine();
        out.flush();

        message = in.readLine();
        AuthenticationRequest authenticationRequest = decodeMessage2(message);

        myLastNounce = newNounce();
        String authentication = encodeMessage3(password, authenticationRequest.getSalt(),
                authenticationRequest.getCounter(), authenticationRequest.getN1() + 1, myLastNounce, movieId);
        out.write(authentication);
        out.newLine();
        out.flush();

        message = in.readLine();
        PaymentRequest paymentRequest = decodeMessage4(password, message, myLastNounce);
        if (paymentRequest.getN2_() != myLastNounce + 1)
            throw new Exception();

        myLastNounce = newNounce();
        String payment = encodeMessage5(password, paymentRequest.getN3() + 1, myLastNounce, "pooopystinky");
        out.write(payment);
        out.newLine();
        out.flush();

        message = in.readLine();
        TicketCredentialsReturn ticketCredentials = decodeMessage6(password, message, myLastNounce);
        if (ticketCredentials.getN4_() != myLastNounce + 1)
            throw new Exception();

        clientSocket.close();

        return ticketCredentials;
    }

    private int newNounce() {
        int random;
        do {
            random = new SecureRandom().nextInt();
        } while (nounces.contains(random));

        nounces.add(random);

        return random;
    }

    private Map<String, UserProxy> getUsers(String pathToUserProxiesJSON) throws IOException {
        String UserProxiesJSON = new String(Files.readAllBytes(Paths.get(pathToUserProxiesJSON)));

        Type type = new TypeToken<Map<String, UserProxy>>() {
        }.getType();

        return new Gson().fromJson(UserProxiesJSON, type);
    }

    private Map<String, CipherMovie> getMovies(String pathToCipherMoviesJSON) throws IOException {
        String CipherMoviesJSON = new String(Files.readAllBytes(Paths.get(pathToCipherMoviesJSON)));

        Type type = new TypeToken<Map<String, CipherMovie>>() {
        }.getType();

        return new Gson().fromJson(CipherMoviesJSON, type);
    }

}
