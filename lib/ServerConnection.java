package lib;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.net.UnknownHostException;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Server Connection Class for handling server/client socket connections,
 * read/write buffers and input/output streams (and writing/reading to streams)
 *
 * @author Reece Notargiacomo, Jesse Fletcher, Caleb Fetzer, Alexander Popoff-Asotoff
 * @date 17th May
 *
 */

public class ServerConnection {
	private PrintWriter writer;
	private BufferedReader reader;
	private SSLSocket sslSocket = null;
	public boolean busy = false;
	public boolean connected = false;
	public String public_key;
	private String ip;
	private int port;

	public ServerConnection(SSLSocket socket) {
		sslSocket = socket;
		this.connected = startServer();
	}

	public ServerConnection(String myip, int myport) {
		ip = myip;
		port = myport;
		try {
			// SSL Socket
			SSLSocketFactory sslsf = (SSLSocketFactory)SSLSocketFactory.getDefault();
			sslSocket = (SSLSocket)sslsf.createSocket(ip, port);
			this.connected = startServer();

		} catch (UnknownHostException e) {
			System.out.println("No host found at "+ip+":"+port+".");

		} catch (IOException e) {
			System.out.println("No listening host at "+ip+":"+port+".");
		}
	}

	public boolean startServer() {
		try {
			// Create input buffer
			InputStream inputstream = sslSocket.getInputStream();
			InputStreamReader inputstreamreader = new InputStreamReader(inputstream);
			reader = new BufferedReader(inputstreamreader);

			// Create output stream
			OutputStream outputStream = sslSocket.getOutputStream();
			writer = new PrintWriter(outputStream);

			return true;
		} catch (Exception err) {
			System.err.println(err);
			System.out.println("GETTING TO START THE SERVER BRUH");
			return false;
		}
	}

	public boolean reconnect() {
		if(sslSocket==null && ip != null)
			try {
				SSLSocketFactory sslsf = (SSLSocketFactory)SSLSocketFactory.getDefault();
				sslSocket = (SSLSocket)sslsf.createSocket(ip, port);
			} catch(Exception er) {
				System.out.println("Fuck");
				return false;
			}

		this.close();
		this.connected = startServer();

		return connected;
	}

	public boolean send(String msg) throws IOException {
		try {
			writer.write(msg + "\n");
			writer.flush();

			if(writer.checkError()){
				this.close();
				return false;
			}

			return true;
		} catch (NullPointerException err) {
			this.close();
			throw new IOException("No Socket");

		}
	}

	public String receive() throws IOException {
		try {
			writer.flush();
			return (new String(reader.readLine()));
		} catch (NullPointerException err) {
			this.close();
			System.out.println("SHITCUNTMOTHERFUCK");
			throw new IOException("No Socket");
		}
	}

	public String request(String msg) throws IOException  {
		send( msg );
		return receive();
	}

	public void close() {
		try{
			this.connected = false;
			this.sslSocket.close();
		}catch(Exception err) {
			//err.printStackTrace();
		}
	}
}
