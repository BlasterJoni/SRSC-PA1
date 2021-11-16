package srsc.srtsp;

import srsc.Utils;
import srsc.UtilsBase;

import java.io.IOException;
import java.net.*;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class SRTSPDatagramSocket extends DatagramSocket {

    byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f };

    SecretKeySpec key;
    Cipher cipher;
    Mac hMac;
    Key hMacKey;
    IvParameterSpec ivSpec;

    public SRTSPDatagramSocket() throws Exception {
        super();
        key = new SecretKeySpec(keyBytes, "RC4");
        cipher = Cipher.getInstance("RC4");
        hMac = Mac.getInstance("HmacSHA512");
        hMacKey = new SecretKeySpec(key.getEncoded(), "HmacSHA512");

        // ivSpec = null;
    }

    public SRTSPDatagramSocket(SocketAddress inSocketAddress) throws Exception {
        super(inSocketAddress);
        key = new SecretKeySpec(keyBytes, "RC4");
        cipher = Cipher.getInstance("RC4");
        hMac = Mac.getInstance("HmacSHA512");
        hMacKey = new SecretKeySpec(key.getEncoded(), "HmacSHA512");

        // ivSpec = null;
    }

    @Override
    public void send(DatagramPacket p) throws IOException {

        byte[] payload = p.getData();

        byte version = 0b00010000;
        byte messageType = 0b00000000;
        byte versionPlusMsgType = (byte) (version | messageType);

        int headerSize = Byte.SIZE / 8 + Integer.SIZE / 8;
        int payloadSize = p.getLength();
        int macSize = hMac.getMacLength();

        try {
            cipher.init(Cipher.ENCRYPT_MODE, key);

            byte[] cipherText = new byte[cipher.getOutputSize(payloadSize + macSize)];

            int ctLength = cipher.update(payload, 0, payloadSize, cipherText, 0);

            hMac.init(hMacKey);
            hMac.update(payload, 0, payloadSize);

            ctLength += cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, ctLength);

            byte[] packetData = ByteBuffer.allocate(headerSize+ctLength).put(versionPlusMsgType).putInt(payloadSize).put(cipherText).array();           
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

        int headerSize = Byte.SIZE / 8 + Integer.SIZE / 8;
        byte versionPlusMsgType = packetData.get();
        byte version = (byte) (0b11110000 & versionPlusMsgType);
        byte messageType = (byte) (0b00001111 &  versionPlusMsgType);

        int payloadAndHMacSize = p.getLength()-headerSize;
        int payloadSize = packetData.getInt();

        byte[] cipherText = new byte[payloadAndHMacSize];
        packetData.get(cipherText);

        try {
            cipher.init(Cipher.DECRYPT_MODE, key);

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
