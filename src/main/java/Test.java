
/** 
 * Materiais/Labs para SRSC 17/18, Sem-2
 * Henrique Domingos, 12/3/17
 **/
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.time.temporal.TemporalUnit;

import javax.crypto.KeyGenerator;

import com.google.gson.Gson;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.File;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.PrivateKey;

import srsc.Utils;
import srsc.configEntities.Coin;
import srsc.configEntities.CoinWithIntegrity;
import srsc.configEntities.IssuedCoin;
import srsc.configEntities.SignedCoin;

public class Test {

    public static void main(String[] args) throws Exception {
        // String s = "kek";
        // byte[] a = srsc.Utils.toByteArray(s);
        // String s1 = srsc.Utils.toString(a);

        // System.out.println(s);
        // System.out.println(a);
        // System.out.println(s1);

        // byte[] a1 = { 0b00000001, 0b00000010, 0b00000011};
        // String s2 = srsc.Utils.toString(a1);
        // byte[] a2 = srsc.Utils.toByteArray(s2);

        // System.out.print((int) a1[0]);
        // System.out.print(s2);
        // System.out.print((int) a2[2]);

        /*
         * // Generate proxy box id
         * 
         * KeyStore ks = KeyStore.getInstance(new
         * File("./src/main/resources/proxybox.keystore"), "password".toCharArray());
         * byte[] pub = ks.getCertificate("proxybox").getPublicKey().getEncoded();
         * byte[] ran = new byte[32]; new SecureRandom().nextBytes(ran);
         * 
         * System.out.print(Utils.toHex(ByteBuffer.allocate(pub.length+ran.length).put(
         * pub).put(ran).array()));
         */

        /*
         * // Gerar chaves
         * 
         * KeyGenerator kg = KeyGenerator.getInstance("DES"); // kg.init(256, new
         * SecureRandom()); // System.out.println("key aes");
         * System.out.println(Utils.toHex(kg.generateKey().getEncoded())); byte[] iv =
         * new byte[8]; new SecureRandom().nextBytes(iv);
         * System.out.println("iv array"); System.out.println(Utils.toHex(iv));
         * 
         * System.out.println("hmac");
         * System.out.println(Utils.toHex(KeyGenerator.getInstance("HmacSHA512").
         * generateKey().getEncoded()));
         */

        // Gerar moedas

        Security.addProvider(new BouncyCastleProvider());

        Coin c = new Coin("PPVMovieCoin", "BancoBank", 10, java.time.LocalDate.now().plusMonths(12).toString());

        KeyPairGenerator ckpg = KeyPairGenerator.getInstance("EC", "BC");
        KeyPair cK = ckpg.generateKeyPair();
        Signature signatureC = Signature.getInstance("SHA512withECDSA", "BC");
        signatureC.initSign(cK.getPrivate(), new SecureRandom());
        signatureC.update(c.toByteArray());
        byte[] CsigBytes = signatureC.sign();

        SignedCoin s = new SignedCoin(c, cK.getPublic().getEncoded(), CsigBytes);

        KeyStore iK = KeyStore.getInstance(new File("./src/main/resources/bancobank.keystore"),
                "password".toCharArray());
        Signature signatureI = Signature.getInstance("SHA512withECDSA", "BC");
        signatureI.initSign((PrivateKey) iK.getKey("bancobank", "password".toCharArray()), new SecureRandom());
        signatureI.update(s.toByteArray());
        byte[] IsigBytes = signatureI.sign();

        IssuedCoin i = new IssuedCoin(s, iK.getCertificate("bancobank").getPublicKey().getEncoded(), IsigBytes);

        MessageDigest hash1 = MessageDigest.getInstance("SHA256", "BC");
        byte[] hashed1 = hash1.digest(i.toByteArray());

        MessageDigest hash2 = MessageDigest.getInstance("SHA512", "BC");
        byte[] hashed2 = hash2.digest(i.toByteArray());

        CoinWithIntegrity cwi = new CoinWithIntegrity(i, hashed1, hashed2);

        Gson gson = new Gson();
        String json = gson.toJson(cwi);
        System.out.println(json);

        // CoinWithIntegrity fj = gson.fromJson(json, CoinWithIntegrity.class);

        // String json2 = gson.toJson(fj); // System.out.println(json2);

    }
}
