package srsc.srtsp;

import srsc.Utils;
import srsc.configEntities.Ciphersuite;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.Key;
import java.security.MessageDigest;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SRTSPDatagramSocket extends DTLSSocket {

    private static final int HEADERSIZE = Byte.SIZE / 8 + Byte.SIZE / 8 + Integer.SIZE / 8;

    private static final byte VERSION = 0b00000011;
    private static final byte MESSAGE = 0b00000000;

    SecretKeySpec key;
    Cipher cipher;
    Mac hMac;
    Key hMacKey;
    IvParameterSpec ivSpec = null;

    public SRTSPDatagramSocket(Ciphersuite c, boolean isServer, String keystore, String keystorePassword, String truststore, String truststorePassword, String dtlsConf, SocketAddress destAddress, SocketAddress ourAddress) throws Exception {
        super(isServer, keystore, keystorePassword, truststore, truststorePassword, dtlsConf, ourAddress);
        super.beginHandshake(destAddress);
        key = new SecretKeySpec(c.getConfidentiality().getKey(), c.getConfidentiality().getKeySpec());
        if(c.getConfidentiality().getIv()!=null)
            ivSpec = new IvParameterSpec(c.getConfidentiality().getIv());
        cipher = Cipher.getInstance(c.getConfidentiality().getSpec());
        hMac = Mac.getInstance(c.getIntegrity().getSpec());
        hMacKey = new SecretKeySpec(c.getIntegrity().getKey(), c.getIntegrity().getKeySpec());
    }

    @Override
    public void send(DatagramPacket p) throws IOException {

        byte[] payload = p.getData();

        int payloadSize = p.getLength();
        int macSize = hMac.getMacLength();

        try {
            if(ivSpec==null)
                cipher.init(Cipher.ENCRYPT_MODE, key);
            else
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

            byte[] cipherText = new byte[cipher.getOutputSize(payloadSize + macSize)];

            int ctLength = cipher.update(payload, 0, payloadSize, cipherText, 0);

            hMac.init(hMacKey);
            hMac.update(payload, 0, payloadSize);

            ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);

            byte[] packetData = ByteBuffer.allocate(HEADERSIZE+ctLength).put(VERSION).put(MESSAGE).putInt(payloadSize).put(cipherText).array();           
            super.send(new DatagramPacket(packetData, packetData.length, p.getSocketAddress()));

        }  catch (Exception e) {
            e.printStackTrace();
            throw new IOException();
        }  
    }

    @Override
    public void receive(DatagramPacket p) throws IOException {
        super.receive(p);

        byte[] packetDataArray = p.getData();
        ByteBuffer packetData = ByteBuffer.wrap(packetDataArray);

        byte version = packetData.get();
        byte messageType = packetData.get();

        int payloadAndHMacSize = p.getLength()-HEADERSIZE;
        int payloadSize = packetData.getInt();

        byte[] cipherText = new byte[payloadAndHMacSize];
        packetData.get(cipherText);

        try {
            if(ivSpec==null)
                cipher.init(Cipher.DECRYPT_MODE, key);
            else
                cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

            byte[] plainText = cipher.doFinal(cipherText, 0, payloadAndHMacSize);

            hMac.init(hMacKey);
            hMac.update(plainText, 0, payloadSize);

            byte[] payloadHash = new byte[hMac.getMacLength()];
            System.arraycopy(plainText, payloadSize, payloadHash, 0, payloadHash.length);

            if(!MessageDigest.isEqual(hMac.doFinal(), payloadHash)){
                throw new Exception();
            }
            else{
                //p.setData(plainText, 0, payloadSize); // isto troca a referencia do array q tem la dentro pa uma referencia do plaintext
                System.arraycopy(plainText, 0, packetDataArray, 0, payloadSize); // isto copia o valor das coisas po array q ja la ta
                p.setLength(payloadSize);
            }
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException();
        }       

    }
}
