package srsc;/* Implements a service supporting user authentication, and for authenticated/registered users provides
 * the establishment of security association parameters – including cryptographic keys or other secrecy parameters), to allow
 * the src.srsc.proxy to receive real-time protected streams and to decode them to be sent for playing with the media player tool;
 */
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.Properties;

import srsc.sadkdp.SADKDP;

public class SignalingServer {

    static public void main(String[] args) throws Exception {
        InputStream inputStream = new FileInputStream("./src/main/resources/config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);

        if (args.length != 7) {
			System.out.println("Erro, usar: SignalingServer <userproxies> <ciphermovies> <keystore> <keystore-password> <truststore> <truststore-password> <tls-conf>");
			System.exit(-1);
		}

        SADKDP server = new SADKDP(args[2], args[3]); //keystore, keystorepassword
        server.startServer(properties.getProperty("signaling"), properties.getProperty("streaming"), args[0], args[1]); //port, userproxies, ciphermovies
    }
    
}
