package srsc;

/* CHANGE TO READ SYMMETRIC AND HMAC
 *
 * This is a very simple (transparent) UDP src.srsc.proxy
 * The src.srsc.proxy can listening on a remote source (server) UDP sender
 * and transparently forward received datagram packets in the
 * delivering endpoint
 *
 * Possible Remote listening endpoints:
 *    Unicast IP address and port: configurable in the file config.properties
 *    Multicast IP address and port: configurable in the code
 *  
 * Possible local listening endpoints:
 *    Unicast IP address and port
 *    Multicast IP address and port
 *       Both configurable in the file config.properties
 * 
 * A component to receive the protected streams (in the communication channel used by the SreamingServer for
 * the media dissemination). At the src.srsc.proxy level, the media frames must be processed to be decrypted and to control the
 * required integrity , and then the streams are sent (decrypted – or in clear-format) to be played by the media player tool.
 *
 */

import java.io.FileInputStream;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketAddress;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Properties;
import java.util.Set;
import java.util.stream.Collectors;

import srsc.sadkdp.SADKDP;
import srsc.sadkdp.jsonEntities.TicketCredentialsReturn;
import srsc.srtsp.SRTSPDatagramSocket;
import srsc.srtsp.SRTSP;

class ProxyBox {
    public static void main(String[] args) throws Exception {
        InputStream inputStream = new FileInputStream("./src/main/resources/config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
        String streamingUDP = properties.getProperty("streamingUDP");
        String proxyUDP = properties.getProperty("proxyUDP");
        String destinations = properties.getProperty("localdelivery");

        if (args.length != 10) {
			System.out.println("Erro, usar: ProxyBox <movieId> <username> <password> <ProxyInfo> <keystore> <keystore-password> <truststore> <truststore-password> <tls-conf> <dtls-conf>");
			System.exit(-1);
		}
        TicketCredentialsReturn tc = new SADKDP(args[4], args[5], args[6], args[7], args[8]).getTicket(properties.getProperty("signaling"), args[1], args[2], new String(Files.readAllBytes(Paths.get(args[3]))), args[0]);
        new SRTSP(args[4], args[5], args[6], args[7], args[8]).requestMovie(tc);
        
        SocketAddress streamingSocketAddress = parseSocketAddress(streamingUDP);
        SocketAddress inSocketAddress = parseSocketAddress(proxyUDP);
        Set<SocketAddress> outSocketAddressSet = Arrays.stream(destinations.split(",")).map(s -> parseSocketAddress(s))
                .collect(Collectors.toSet());

        DatagramSocket inSocket = new SRTSPDatagramSocket(tc.getCiphersuiteConf(), false, args[4], args[5], args[6], args[7], args[9], streamingSocketAddress, inSocketAddress);
        DatagramSocket outSocket = new DatagramSocket();
        byte[] buffer = new byte[4 * 1024];

        while (true) {
            DatagramPacket inPacket = new DatagramPacket(buffer, buffer.length);
            inSocket.receive(inPacket); // if remote is unicast

            if(inPacket.getLength() == 1 && buffer[0]==0x04) // eot ascii character
                break;

            System.out.print("*");
            for (SocketAddress outSocketAddress : outSocketAddressSet) {
                outSocket.send(new DatagramPacket(buffer, inPacket.getLength(), outSocketAddress));
            }
        }
    }

    private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
