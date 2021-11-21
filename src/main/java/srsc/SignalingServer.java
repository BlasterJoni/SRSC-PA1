package srsc;/* Implements a service supporting user authentication, and for authenticated/registered users provides
 * the establishment of security association parameters – including cryptographic keys or other secrecy parameters), to allow
 * the src.srsc.proxy to receive real-time protected streams and to decode them to be sent for playing with the media player tool;
 */
import srsc.sadkdp.SADKDP;

public class SignalingServer {

    static public void main(String[] args) throws Exception {
        if (args.length != 4) {
			System.out.println("Erro, usar: SignalingServer <keystore> <keystore-password> <userproxies> <ciphermovies>");
			System.exit(-1);
		}

        SADKDP server = new SADKDP(args[0], args[1]); //keystore, keystorepassword
        server.startServer(42069, args[2], args[3]); //port, userproxies, ciphermovies
    }
    
}
