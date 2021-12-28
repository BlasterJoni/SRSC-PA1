package srsc;

import java.io.*;
import java.net.*;
import java.util.Properties;

import srsc.srtsp.jsonEntities.TicketCredentials;
import srsc.srtsp.SRTSP;
import srsc.srtsp.SRTSPDatagramSocket;

class StreamingServer {

	static public void main(String[] args) throws Exception {
		InputStream inputStream = new FileInputStream("./src/main/resources/config.properties");
        if (inputStream == null) {
            System.err.println("Configuration file not found!");
            System.exit(1);
        }
        Properties properties = new Properties();
        properties.load(inputStream);
		String streamingUDP = properties.getProperty("streamingUDP");

		if (args.length != 6) {
			System.out.println("Erro, usar: StreamingServer <keystore> <keystore-password> <truststore> <truststore-password> <tls-conf> <dtls-conf>");
			System.exit(-1);
		}

		SRTSP srtsp = new SRTSP(args[0], args[1]);
		while (true) {
			TicketCredentials tc = srtsp.startReceiveTicket(42169);

			int size;
			int count = 0;
			long time;
			DataInputStream g = new DataInputStream( new FileInputStream("./src/main/resources/movies/" + tc.getMovieId() + ".dat"));
			byte[] buff = new byte[4096];

			InetSocketAddress addr = srtsp.getClientAddress();
			SocketAddress streamingSocketAddress = parseSocketAddress(streamingUDP);
			DatagramSocket s = new SRTSPDatagramSocket(tc.getCiphersuiteConf(), true, args[0], args[1], args[2], args[3], args[5], addr, streamingSocketAddress);
			DatagramPacket p = new DatagramPacket(buff, buff.length, addr);
			long t0 = System.nanoTime(); // tempo de referencia para este processo
			long q0 = 0;

			while (g.available() > 0) {
				size = g.readShort();
				time = g.readLong();
				if (count == 0)
					q0 = time; // tempo de referencia no stream
				count += 1;
				g.readFully(buff, 0, size);
				p.setData(buff, 0, size);
				p.setSocketAddress(addr);
				long t = System.nanoTime();
				Thread.sleep(Math.max(0, ((time - q0) - (t - t0)) / 1000000));

				// send packet (with a frame payload)
				// Frames sent in clear (no encryption)
				s.send(p);
				System.out.print(".");
			}
			byte[] endOfTransmission = {0x04}; // eot ascii character
			p.setData(endOfTransmission);
			p.setSocketAddress(addr);
			s.send(p);

			System.out.println("DONE! all frames sent: " + count);
		}
	}

	private static InetSocketAddress parseSocketAddress(String socketAddress) {
        String[] split = socketAddress.split(":");
        String host = split[0];
        int port = Integer.parseInt(split[1]);
        return new InetSocketAddress(host, port);
    }
}
