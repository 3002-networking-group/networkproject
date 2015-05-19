import java.io.*;
import java.security.PublicKey;
import java.util.Random;
import java.util.Arrays;
import java.security.*;
import javax.net.ssl.*;
import java.net.*;
import lib.*;

/**
 * Collector Class
 * @author Jesse Fletcher, Caleb Fetzer, Reece Notargiacomo, Alexander Popoff-Asotoff
 * @version 5.9.15
 */

public class Collector extends Node {

	private ECentWallet eCentWallet; // file for holding ecents
	private final static String ECENTWALLET_FILE = "collector.wallet";

	private ServerConnection bank, director;
	private boolean bankConn, dirConn;

	private int xpos = 0, ypos = 0;

	public static void main(String[] args) throws IOException {
		load_ip_addresses(args);
		new Collector();
	}

	/**
	 * Collector
	 */
	public Collector() throws IOException {
		set_type("COLLECTOR");
		SSLHandler.declareClientCert("SSL_Certificate","cits3002");

		bankConn = false;
		dirConn = false;

		getServers();
	}

	private void getServers(){	// get bank/dir listening address/port
		while(!bankConn || !dirConn){
			startUDP();		// get addresses from UDP socket
		}
		start();
	}

	private void start(){
		try{
			// Initiate eCentWallet
			eCentWallet = new ECentWallet( ECENTWALLET_FILE );

			if (eCentWallet.isEmpty())
				buyMoney(100);

			ANNOUNCE(eCentWallet.displayBalance());

			if(initiateWithDirector())
				System.out.println(analyse_data("DATA"));
		}catch (IOException e){
			ALERT("Problem analysing data");
		}

	}

	private void startUDP(){
		try{
			DatagramSocket socket = new DatagramSocket(1566);

			byte[] data = new byte[1024];
			DatagramPacket datagram = new DatagramPacket(data, data.length);

			socket.receive(datagram);

			Message packet= new Message(new String(datagram.getData(), 0, datagram.getLength(), "utf-8"));

			switch (packet.getFlagEnum()) {
				case DIR:
					ALERT("Recieved Address:Port UDP from Director");
					directorIPAddress = packet.data.split(";")[0];
					dirPort = Integer.parseInt(packet.data.split(";")[1]);

					dirConn = true;
					break;
				case BANK:
					ALERT("Recieved Address:Port UDP from Bank");
					bankIPAddress = packet.data.split(";")[0];
					bankPort = Integer.parseInt(packet.data.split(";")[1]);

					bankConn = true;
					break;
			}
			if(packet==null){
				ALERT("UDP: Error listening for Bank/Director address and port...");
			}
			socket.close();
		}catch (SocketException e){
			ALERT("Error creating socket to listen on: Port 1566 in use");
		}catch (IOException e){
			ALERT("Error receiving datagram from UDP server");
		}
	}

	private void buyMoney(int amount){

		ALERT("Sending Money Withdrawl Request..");
		String withdrawl_request = MessageFlag.BANK_WIT + ":" + amount;
		boolean sent = false;

		while(!sent)
			try {
				bank = new ServerConnection(bankIPAddress, bankPort);

				sent = bank.send(withdrawl_request);
			} catch (IOException err) {
				ALERT_WITH_DELAY("Could not send request. Retrying...");
			}

		String eCent;
		String[] eCentBuffer = new String[amount];
		int index = 0;

		while(index < amount)
			try {
				eCent = bank.receive();
				eCentBuffer[index++] = eCent;
			} catch (IOException err) {
				ALERT_WITH_DELAY("Connection interrupted. Retrying...");
				bank.reconnect();
			}

		bank.close();

		eCentWallet.add(eCentBuffer);
	}

	private boolean initiateWithDirector()
	{
		String connect_director = MessageFlag.C_INIT + ":DATA";
		String result = null;

		while (result == null)
			try {
				director = new ServerConnection(directorIPAddress, dirPort);

				result = director.request(connect_director);
			} catch(IOException err) {
				ALERT_WITH_DELAY("Could not contact director. Retrying...");
				director.reconnect();
			}
		director.close();

        	return result != null;
	}
	// Verify a public key from Director was issued by bank (must be from analyst)
	private boolean verifyPubKey(String pubKey){
		try{
			bank = new ServerConnection(bankIPAddress, bankPort);

			Message result = new Message(bank.request(MessageFlag.PUB_AUT + ":" + pubKey));

			bank.close();

			switch(result.getFlagEnum()) {
				case VALID:
					ALERT("Analyst public key verified.");
					return true;
				case INVALID:
					return false;
			}
		}catch (IOException err) {
			ALERT_WITH_DELAY("Could not verify Public Key");
		}
		return false;

	}
	private String analyse_data(String dataType) throws IOException {

		ALERT("Connected! (Director)");

		director = new ServerConnection(directorIPAddress, dirPort);

		String temporary_eCent = eCentWallet.remove();

		try {
			director.send(MessageFlag.EXAM_REQ + ":" + dataType);

			ANNOUNCE("Request sent!");

			ALERT("Awaiting response/encryption key...");

			// Read response
			Message msg = new Message(director.receive());

			if(msg.getFlag() == MessageFlag.PUB_KEY) {

				if(verifyPubKey(msg.data)){
					PublicKey analyst_public_key = (PublicKey) KeyFromString(msg.data);
					ALERT("Public key recieved!");

					String data = genStringForData();
					ALERT("Encrypting eCent and data!");
					String encrypted_packet = encrypt(temporary_eCent + ":" + data, analyst_public_key);

					// send encrypted eCent + data
					ALERT("Sending Encrypted Packet!");
					director.send(encrypted_packet);

					Message analysis = new Message (director.receive());
					ALERT("Receiving response...");

					// VALID - Valid result returned
					// DUP - Duplicate Ecent sent
					// RET - Analyst dc before depositing ecent (returnable)
					// INVALID - Invalid Ecent sent (by collector)
					// FAIL - No analysts left in pool (try again later)
					// ERROR - Analyst dc after depositing ecent (invalid/lost)
					switch (analysis.getFlagEnum()) {
						case VALID:
							ALERT("Response recieved!");
							director.close();
							return analysis.data;
						case DUP:
							ALERT("Duplicate Ecent!!! Check wallet integrity");
							break;
						case RET:
							ALERT("Analyst disconnected before depositing Ecent, returning to wallet.");
							eCentWallet.add(temporary_eCent,true);
							break;
						case INVALID:
							ALERT("Invalid Ecent sent from Wallet, check wallet integrity.");
							break;
						case FAIL:
							ALERT("Could not connect to analyst.");
							break;
						case ERROR:
							ALERT("Analyst disconnected after depositing Ecent. Ecent lost.");
							break;
					}
				}else{
					ALERT("Public Key not verified! Check director authenticity");
				}
			}
			director.close();

		} catch(IOException err) {
			// Error in sending
			ALERT("Error: Connection to Director dropped.");
			this.eCentWallet.add( temporary_eCent );
			throw new IOException("Could not analyse data!");
		}

		return null;
	}

	private String genStringForData() {

		String ALPHABET = "gdbac";

		Random r = new Random();
		String randomPattern = new String();
		String randomString = new String();
		int min = 10;
		int max = 100;

		int randomLength = 0;
		randomLength = min + r.nextInt((max - min) +1);
		// will gen a random string using alphabet
		for(int i = 0; i < (randomLength/3); i++)
			randomPattern += Character.toString(ALPHABET.charAt(r.nextInt(ALPHABET.length())));

		for(int i = 0; i < randomLength; i++)
			randomString += Character.toString(ALPHABET.charAt(r.nextInt(ALPHABET.length())));

			// return a string in the format string-striiiing
		return randomPattern + "-" + randomString;
	}
}
