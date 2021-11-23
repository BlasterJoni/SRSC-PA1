package srsc;

import java.io.*;
import java.net.*;

import srsc.srtsp.jsonEntities.TicketCredentials;
import srsc.srtsp.SRTSP;
import srsc.srtsp.SRTSPDatagramSocket;

class StreamingServer {

	static public void main(String[] args) throws Exception {
		if (args.length != 2) {
			System.out.println("Erro, usar: StreamingServer <keystore> <keystore-password>");
			System.out.println("        or: StreamingServer <keystore> <keystore-password>");
			System.exit(-1);
		}

		SRTSP srtsp = new SRTSP(args[0], args[1]);
		while (true) {
			TicketCredentials tc = srtsp.startReceiveTicket(42169);

			int size;
			int count = 0;
			long time;
			DataInputStream g = new DataInputStream(
					new FileInputStream("./src/main/resources/movies/" + tc.getMovieId() + ".dat"));
			byte[] buff = new byte[4096];

			DatagramSocket s = new SRTSPDatagramSocket(tc.getCiphersuiteConf());
			InetSocketAddress addr = srtsp.getClientAddress();
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
				if (count == 1)
					srtsp.sendFirstFrame(buff, size, tc);
				else
					s.send(p);
				System.out.print(".");
			}

			System.out.println("DONE! all frames sent: " + count);
		}
	}

}
