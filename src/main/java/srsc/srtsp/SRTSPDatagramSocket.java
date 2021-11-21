package srsc.srtsp;

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

public class SRTSPDatagramSocket extends DatagramSocket {

    byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f };

    SecretKeySpec key;
    Cipher cipher;
    Mac hMac;
    Key hMacKey;
    IvParameterSpec ivSpec = null;

    public SRTSPDatagramSocket(Ciphersuite c) throws Exception {
        super();
        key = new SecretKeySpec(c.getConfidentiality().getKeyByte(), c.getConfidentiality().getKeySpec());
        if(c.getConfidentiality().getIv()!=null)
            ivSpec = new IvParameterSpec(c.getConfidentiality().getIvByte());
        cipher = Cipher.getInstance(c.getConfidentiality().getSpec());
        hMac = Mac.getInstance(c.getIntegrity().getSpec());
        hMacKey = new SecretKeySpec(c.getIntegrity().getKeyByte(), c.getIntegrity().getKeySpec());
    }

    public SRTSPDatagramSocket(SocketAddress inSocketAddress, Ciphersuite c) throws Exception {
        super(inSocketAddress);
        key = new SecretKeySpec(c.getConfidentiality().getKeyByte(), c.getConfidentiality().getKeySpec());
        if(c.getConfidentiality().getIv()!=null)
            ivSpec = new IvParameterSpec(c.getConfidentiality().getIvByte());
        cipher = Cipher.getInstance(c.getConfidentiality().getSpec());
        hMac = Mac.getInstance(c.getIntegrity().getSpec());
        hMacKey = new SecretKeySpec(c.getIntegrity().getKeyByte(), c.getIntegrity().getKeySpec());
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
            if(ivSpec==null)
                cipher.init(Cipher.ENCRYPT_MODE, key);
            else
                cipher.init(Cipher.ENCRYPT_MODE, key, ivSpec);

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
