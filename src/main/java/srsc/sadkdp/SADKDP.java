package srsc.sadkdp;

import java.io.*;
import java.net.*;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.lang.model.util.ElementScanner6;
import javax.net.ServerSocketFactory;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
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

    private static final int HEADERSIZE = Byte.SIZE / 8 + Byte.SIZE / 8 + Integer.SIZE / 8;

    private static final byte VERSION = 0b00000010;
    private static final byte MESSAGE_1 = 0b00000001;
    private static final byte MESSAGE_2 = 0b00000010;
    private static final byte MESSAGE_3 = 0b00000011;
    private static final byte MESSAGE_4 = 0b00000100;
    private static final byte MESSAGE_5 = 0b00000101;
    private static final byte MESSAGE_6 = 0b00000110;

    private static final byte MESSAGE_90 = 0b01011010;
    private static final byte MESSAGE_91 = 0b01011011;

    Gson gson;
    KeyStore ks, ts;
    String keyStorePassword, trustStorePassword;
    Set<Integer> nounces;
    TLSconfig TLSconf;

    public SADKDP(String pathToKeyStore, String keyStorePassword, String pathToTrustStore, String trustStorePassword,
            String tlsConf) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        this.gson = new Gson();
        String TLSconfigJSON = new String(Files.readAllBytes(Paths.get(tlsConf)));
        this.TLSconf = gson.fromJson(TLSconfigJSON, TLSconfig.class);
        this.ks = KeyStore.getInstance("pkcs12");
        ks.load(new FileInputStream(pathToKeyStore), keyStorePassword.toCharArray());
        this.ts = KeyStore.getInstance("pkcs12");
        ts.load(new FileInputStream(pathToTrustStore), trustStorePassword.toCharArray());
        this.keyStorePassword = keyStorePassword;
        this.trustStorePassword = trustStorePassword;
        this.nounces = new HashSet<>();
    }

    private String encodeMessage1(String UserID, String ProxyBoxId) {
        Hello content = new Hello(UserID, ProxyBoxId);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + payloadSize).put(VERSION).put(MESSAGE_1).putInt(payloadSize)
                .put(payload).array();

        System.out.println("Msg1 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private Hello decodeMessage1(String dataString) throws Exception {

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
        Hello returnObj = gson.fromJson(message, Hello.class);

        return returnObj;
    }

    private String encodeMessage2(int N1, byte[] Salt, int Counter) {
        AuthenticationRequest content = new AuthenticationRequest(N1, Salt, Counter);
        String message = gson.toJson(content);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + payloadSize).put(VERSION).put(MESSAGE_2).putInt(payloadSize)
                .put(payload).array();

        System.out.println("Msg2 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private AuthenticationRequest decodeMessage2(String dataString) throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg2 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

        if (version != VERSION || messageType != MESSAGE_2)
            throw new Exception();

        int payloadSize = dataBuff.getInt();
        byte[] payload = new byte[payloadSize];
        dataBuff.get(payload);
        String message = Utils.toString(payload);
        AuthenticationRequest returnObj = gson.fromJson(message, AuthenticationRequest.class);

        return returnObj;
    }

    private String encodeMessage3(String password, byte[] salt, int counter, int n1_ /* n1+1 */, int n2, String movieId)
            throws Exception {
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

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + encryptedPayloadSize + intCheckSize).put(VERSION).put(MESSAGE_3)
                .putInt(encryptedPayloadSize).put(encryptedPayload).put(integrityCheck).array();

        System.out.println("Msg3 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private Authentication decodeMessage3(String password, byte[] salt, int counter, String dataString,
            int myLastNounce) throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg3 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

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
        hMac.update(Utils.toByteArray(myLastNounce + 1));
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

    private String encodeMessage4(String password, int price, int n2_, int n3) throws Exception {
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

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + sigEnvPayloadSize + intCheckSize).put(VERSION).put(MESSAGE_4)
                .putInt(sigEnvPayloadSize).put(sigEnvPayload).put(integrityCheck).array();

        System.out.println("Msg4 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private PaymentRequest decodeMessage4(String password, String dataString, int myLastNounce) throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg4 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

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
        hMac.update(Utils.toByteArray(myLastNounce + 1));
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

    private String encodeMessage5(String password, int n3_, int n4, CoinWithIntegrity paymentCoin) throws Exception {
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

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + sigEnvPayloadSize + intCheckSize).put(VERSION).put(MESSAGE_5)
                .putInt(sigEnvPayloadSize).put(sigEnvPayload).put(integrityCheck).array();

        System.out.println("Msg5 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private Payment decodeMessage5(String password, String dataString, int myLastNounce) throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg5 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

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
        hMac.update(Utils.toByteArray(myLastNounce + 1));
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

    private String encodeMessage6(String password, String ip, String port, String movieId, Ciphersuite ciphersuitConf,
            byte[] sessionKey, byte[] sessionIV, byte[] macKey, int n4_, int nc1) throws Exception {
        TicketCredentials content1 = new TicketCredentials(ip, port, movieId, ciphersuitConf, sessionKey, sessionIV,
                macKey, n4_);
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

        TicketCredentials content2 = new TicketCredentials(ip, port, movieId, ciphersuitConf, sessionKey, sessionIV,
                macKey, nc1);
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

        TicketCredentialsMessage content = new TicketCredentialsMessage(encryptedPayload1, encryptedPayload2, sigBytes1,
                sigBytes2);
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

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + payloadSize + intCheckSize).put(VERSION).put(MESSAGE_6)
                .putInt(payloadSize).put(payload).put(integrityCheck).array();

        System.out.println("Msg6 Sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private TicketCredentialsReturn decodeMessage6(String password, String dataString, int myLastNounce)
            throws Exception {
        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg6 Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

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
        hMac.update(Utils.toByteArray(myLastNounce + 1));
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
                tpbObj.getCiphersuiteConf(), tpbObj.getSessionKey(), tpbObj.getSessionIV(), tpbObj.getMacKey(),
                tpbObj.getN4_(), tcm.getTicketForStreamingServer(), tcm.getSignatureStreamingServer());
    }

    private String encodeError(String password, byte messageType, String errorCode) throws Exception {
        ErrorAlert errorAlert = new ErrorAlert(messageType, errorCode);
        String message = gson.toJson(errorAlert);
        byte[] payload = Utils.toByteArray(message);
        int payloadSize = payload.length;

        Mac hMac = Mac.getInstance("HmacSHA512");
        Key hMacKey = new SecretKeySpec(password.getBytes(), "HmacSHA512");
        int intCheckSize = hMac.getMacLength();
        hMac.init(hMacKey);
        hMac.update(Utils.toByteArray(message));
        byte[] integrityCheck = hMac.doFinal();

        byte[] toRet = ByteBuffer.allocate(HEADERSIZE + payloadSize + intCheckSize).put(VERSION).put(messageType)
                .putInt(payloadSize).put(payload).put(integrityCheck).array();

        System.out.println("Error message sent: " + Utils.toHex(toRet));

        return Utils.toHex(toRet);
    }

    private void decodeError(String password, String dataString) throws Exception {

        byte[] data = Utils.hexStringToByteArray(dataString);
        System.out.println("Msg Received: " + Utils.toHex(data));
        ByteBuffer dataBuff = ByteBuffer.wrap(data);

        byte version = dataBuff.get();
        byte messageType = dataBuff.get();

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

    public void startServer(String signalingAddress, String streamingAddress, String pathToUserProxiesJSON,
            String pathToCipherMoviesJSON) throws Exception {

        Map<String, UserProxy> users = getUsers(pathToUserProxiesJSON);
        Map<String, CipherMovie> movies = getMovies(pathToCipherMoviesJSON);

        SSLContext sc = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        kmf.init(ks, keyStorePassword.toCharArray());
        tmf.init(ts);
        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        SSLServerSocketFactory ssf = sc.getServerSocketFactory();
        SSLServerSocket serverSocket = (SSLServerSocket) ssf
                .createServerSocket(Integer.parseInt(signalingAddress.split(":")[1]));

        switch (TLSconf.getAuthentication()) {
            case "MUTUAL":
                serverSocket.setUseClientMode(false);
                serverSocket.setNeedClientAuth(true);
                break;
            case "SSERVER":
                serverSocket.setUseClientMode(false);
                serverSocket.setNeedClientAuth(false);
                break;
            case "PROXY":
                serverSocket.setUseClientMode(true);
                break;
        }

        serverSocket.setEnabledProtocols(new String[] { TLSconf.getVersion() });
        serverSocket.setEnabledCipherSuites(TLSconf.getCiphersuites());

        // ServerSocket serverSocket = new
        // ServerSocket(Integer.parseInt(signalingAddress.split(":")[1]));

        while (true) {
            SSLSocket clientSocket = (SSLSocket) serverSocket.accept();
            // Socket clientSocket = serverSocket.accept();
            BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            String message;
            int myLastNounce;
            int counter = 1;
            String password = "";

            try {
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
                password = users.get(hello.getUserId()).getPassword();
                Authentication authentication = decodeMessage3(password, Salt, counter++, message, myLastNounce);
                if (authentication.getN1_() != myLastNounce + 1 || !movies.containsKey(authentication.getMovieId()))
                    throw new Exception();
                addSeenNounce(authentication.getN1_());
                CipherMovie movie = movies.get(authentication.getMovieId());

                myLastNounce = newNounce();
                String paymentrequest = encodeMessage4(password, movie.getPpvprice(), authentication.getN2() + 1,
                        myLastNounce);
                out.write(paymentrequest);
                out.newLine();
                out.flush();

                message = in.readLine();
                Payment payment = decodeMessage5(password, message, myLastNounce);
                if (payment.getN3_() != myLastNounce + 1 || !checkCoin(movie.getPpvprice(), payment.getPaymentCoin()))
                    throw new Exception();
                addSeenNounce(payment.getN3_());

                KeyGenerator kg = KeyGenerator.getInstance("AES");
                kg.init(256);
                SecretKey sessionKey = kg.generateKey();
                SecretKey macKey = kg.generateKey();

                byte[] iv = new byte[16];
                new SecureRandom().nextBytes(iv);

                String ticketcredentials = encodeMessage6(password, streamingAddress.split(":")[0],
                        streamingAddress.split(":")[1], movie.getMovie(),
                        movie.getCiphersuite(), sessionKey.getEncoded(), iv, macKey.getEncoded(), payment.getN4() + 1,
                        newNounce());
                out.write(ticketcredentials);
                out.newLine();
                out.flush();
            } catch (Exception e) {
                e.printStackTrace();
                String error = encodeError(password, MESSAGE_91, e.getMessage());
                out.write(error);
                out.newLine();
                out.flush();
            }
            out.close();
            in.close();

            clientSocket.close();
        }
        // serverSocket.close();

    }

    public TicketCredentialsReturn getTicket(String address, String username, String password, String proxyId,
            String movieId) throws Exception {

        SSLContext sc = SSLContext.getInstance("TLS");
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("PKIX");
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        kmf.init(ks, keyStorePassword.toCharArray());
        tmf.init(ts);
        sc.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        String[] addressSplit = address.split(":");
        SSLSocketFactory factory = (SSLSocketFactory) sc.getSocketFactory();
        SSLSocket clientSocket = (SSLSocket)factory.createSocket(addressSplit[0], Integer.parseInt(addressSplit[1]));

        switch (TLSconf.getAuthentication()) {
            case "MUTUAL": // Nothing to do

            case "SSERVER":
                // I, proxy will be the DTLS client endpoint
                clientSocket.setUseClientMode(true);
                break;
            case "PROXY":
                // I, proxy will be the DTLS server endpoint
                // not requiring the server side authentication
                clientSocket.setUseClientMode(false);
                clientSocket.setNeedClientAuth(false);
                break;
        }

        clientSocket.setEnabledProtocols(new String[] { TLSconf.getVersion() });
        clientSocket.setEnabledCipherSuites(TLSconf.getCiphersuites());

        clientSocket.startHandshake();
        BufferedWriter out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream()));
        BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
        String message;
        int myLastNounce;

        try {
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
            addSeenNounce(paymentRequest.getN2_());

            myLastNounce = newNounce();
            String payment = encodeMessage5(password, paymentRequest.getN3() + 1, myLastNounce,
                    loadCoin(paymentRequest.getPrice()));
            out.write(payment);
            out.newLine();
            out.flush();

            message = in.readLine();
            TicketCredentialsReturn ticketCredentials = decodeMessage6(password, message, myLastNounce);
            if (ticketCredentials.getN4_() != myLastNounce + 1)
                throw new Exception();
            addSeenNounce(ticketCredentials.getN4_());

            out.close();
            in.close();

            clientSocket.close();

            return ticketCredentials;
        } catch (Exception e) {
            String error = encodeError(password, MESSAGE_90, e.getMessage());
            out.write(error);
            out.newLine();
            out.flush();

            out.close();
            in.close();

            clientSocket.close();

            throw e;
        }

    }

    private CoinWithIntegrity loadCoin(int value) throws Exception {

        return gson.fromJson(
                new String(Files.readAllBytes(Paths.get("./src/main/resources/wallet/Coin" + value + ".json"))),
                CoinWithIntegrity.class);

    }

    private boolean checkCoin(int value, CoinWithIntegrity coinWithIntegrity) throws Exception {
        IssuedCoin issuedCoin = coinWithIntegrity.getIssuedCoin();
        SignedCoin signedCoin = issuedCoin.getSignedCoin();
        Coin coin = signedCoin.getCoin();

        MessageDigest hash1 = MessageDigest.getInstance("SHA256", "BC");
        byte[] hashed1 = hash1.digest(issuedCoin.toByteArray());

        if (!MessageDigest.isEqual(hashed1, coinWithIntegrity.getIntegrityProof1()))
            return false;

        MessageDigest hash2 = MessageDigest.getInstance("SHA512", "BC");
        byte[] hashed2 = hash2.digest(issuedCoin.toByteArray());

        if (!MessageDigest.isEqual(hashed2, coinWithIntegrity.getIntegrityProof2()))
            return false;

        if (!Arrays.equals(ks.getCertificate("bancobank").getPublicKey().getEncoded(), issuedCoin.getIssuePublicKey()))
            return false;

        PublicKey keyI = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(issuedCoin.getIssuePublicKey()));
        Signature signatureI = Signature.getInstance("SHA512withECDSA", "BC");
        signatureI.initVerify(keyI);
        signatureI.update(signedCoin.toByteArray());
        if (!signatureI.verify(issuedCoin.getIssueSignature()))
            return false;

        PublicKey keyS = KeyFactory.getInstance("EC")
                .generatePublic(new X509EncodedKeySpec(signedCoin.getCoinPublicKey()));
        Signature signatureS = Signature.getInstance("SHA512withECDSA", "BC");
        signatureS.initVerify((PublicKey) keyS);
        signatureS.update(coin.toByteArray());
        if (!signatureS.verify(signedCoin.getCoinAuthenticity()))
            return false;

        if (coin.getCoinValue() != value)
            return false;

        return true;
    }

    private int newNounce() {
        int random;
        do {
            random = new SecureRandom().nextInt();
        } while (nounces.contains(random + 1));

        return random;
    }

    private void addSeenNounce(int nounce) throws Exception {
        if (!nounces.contains(nounce))
            nounces.add(nounce);
        else
            throw new Exception();
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
