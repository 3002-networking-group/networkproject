import java.io.*;

import javax.net.ssl.*;
import java.util.*;
import java.net.DatagramSocket;
import java.net.DatagramPacket;
import java.net.*;

import java.security.*;

import lib.*;

/**
 * Bank Class For handling Ecent generation, checking and depositing
 *
 * @author Jesse Fletcher, Caleb Fetzer, Reece Notargiacomo, Alexander
 *         Popoff-Asotoff
 * @version 5.9.15
 */

public class Bank extends Node {

	private static int bankPort = 9999;
	private static int sequence = 0;
	private static SSLServerSocket sslserversocket = null;

	private static ECentWallet bankStore;
	private static HashSet<String> depositedEcent;
	private static HashSet<String> validKeys;

	private final static String ECENTWALLET_FILE = "bank.wallet";

	/**
	 * Bank
	 */

	public static void main(String[] args) throws IOException {
		// Option to give the port as an argument
		if (args.length == 1)
			try {
				bankPort = Integer.valueOf(args[0]);
			} catch (NumberFormatException er) {
				bankPort = 9999;
			}

		new Bank();
	}

	public Bank() throws IOException {
		set_type("BANK");
		SSLHandler.declareServerCert("SSL_Certificate", "cits3002");

		bankStore = new ECentWallet(ECENTWALLET_FILE);
		depositedEcent = new HashSet();
		validKeys = new HashSet();

		ANNOUNCE("Starting bank server");

		if (this.startServer()) {

			new Thread(new BankUDP()).start();	// start UDP server to broadcast assigned port and IP
			ANNOUNCE("Bank started on " + getIPAddress() + ":" + bankPort);

			while (true) {
				SSLSocket sslsocket = null;
				try {
					sslsocket = (SSLSocket) sslserversocket.accept();
					ALERT("Accepting a connection!");

				} catch (IOException e) {
					System.out.println("Error connecting client");
				}

				new Thread(new bankConnection(sslsocket)).start(); // start new
																	// thread
			}
		}
	}

	private boolean startServer() {
		try {
			// Use the SSLSSFactory to create a SSLServerSocket to create a
			// SSLSocket
			SSLServerSocketFactory sslserversocketfactory = (SSLServerSocketFactory) SSLServerSocketFactory
					.getDefault();
			sslserversocket = (SSLServerSocket) sslserversocketfactory
					.createServerSocket(bankPort);
			return true;
		} catch (IOException e) {
			ALERT("Could not create server on port " + bankPort);
		}
		return false;
	}

	private class bankConnection implements Runnable {

		protected ServerConnection client;

		public bankConnection(SSLSocket socket) {
			client = new ServerConnection(socket);
		}

		public void run() {
				try {
					Message msg = new Message(client.receive());
					switch (msg.getFlagEnum()) {

						/*
						 * Bank Withdrawal
						 * BANK_WIT => WIT
						 */
						case WIT:
							ALERT("Collector connected  -->  Withdrawing money");

							int amount = Integer.parseInt(msg.data);
							ALERT("Generating " + amount + " eCents!");

							for (int i = 0; i < amount; i++)
								client.send(generateEcent());

							ALERT("Money sent");
							client.close();
							break;


						/*
						 * Bank Deposit
						 * BANK_DEP => DEP
						 */
						case DEP:
							ALERT("Analyst connected  -->  Depositing money");


							if(!depositedEcent.contains(msg.data)){	  // check if it's not duplicate
								if (bankStore.contains(msg.data)) { // Check if eCent is in valid eCent set

									ALERT("Depositing valid eCent");
									ALERT("Sending acknowledgement to Analyst!");
									client.send(MessageFlag.VALID);
									depositedEcent.add(msg.data);
									bankStore.remove(msg.data);


								} else {

									ALERT("Rejecting invalid eCent");
									client.send(MessageFlag.INVALID);

								}
							} else {
								ALERT("Duplicate Ecent");
								client.send(MessageFlag.DUP);
							}
							client.close();
							break;

						case PUBK:
							ALERT("Analyst requesting Keypair..");

							KeyPair keys = generateKeyPair();

							validKeys.add(StringFromKey(keys.getPublic()));		// add to set of valid keys

							client.send(StringFromKey(keys.getPublic()));

							client.send(StringFromKey(keys.getPrivate()));

							client.close();

							ALERT("Keypair Sent");

							break;

						case PUBA:
							ALERT("Collector requesting key verification");

							if(validKeys.contains(msg.data)){
								client.send(MessageFlag.VALID);
							}else{
								client.send(MessageFlag.INVALID);
							}
							client.close();
							break;
						default:
							ALERT("Unexpected input: " + msg.raw());
							break;

					}
					ALERT("Request finished!");
				} catch(IOException err) {
					ALERT("Closing connection");
					client.close();
				}
			}

	}

	public class BankUDP implements Runnable {

		private DatagramSocket socket;

		public BankUDP(){
			try{
				socket = new DatagramSocket(0);		// dynammically allocate any port for broadcasting
			}catch (SocketException e){
				ALERT("Could not establish UDP broadcast server");
			}
		}
		public void run(){
			while(true){
				try{
					String tmp = MessageFlag.B_UDP + ":" + getIPAddress() + ";" + sslserversocket.getLocalPort();
					byte[] message = tmp.getBytes("utf-8");		// encode msg into utf-8 byte array

					InetAddress address = InetAddress.getByName("255.255.255.255");		// get broadcast address

					DatagramPacket packet = new DatagramPacket(message, message.length, address, 1566);	// port 1566 is listening port
					socket.send(packet);

					////////////////// REBROADCAST EVERY X SECONDS ////////////////////
					try{
						System.out.println("SENT UDP -------------");
						Thread.sleep(5000);	// 5 sec
					}
					catch (Exception e){}
				} catch (UnsupportedEncodingException e){
					ALERT("Unsupported encoding: " + e);
				}
				catch (UnknownHostException e){
					ALERT("Unknown UDP host: " + e);
				}
				catch (IOException e){
					ALERT("UDP IO Exception sending broadcast packet");
				}

			}
		}

	}
	private KeyPair generateKeyPair() {
		try {
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(2048);
			return keyGen.generateKeyPair();
			//PrivateKey private_key = pair.getPrivate();
			//PublicKey public_key = pair.getPublic();

		} catch (NoSuchAlgorithmException e) {
			ANNOUNCE("ERROR: Error generating secure socket keys");
			System.exit(-1);
		}
		return null;
	}

	private static String generateEcent() {
		String eCent = getSHA256Hash(Integer.toString(sequence++));

		bankStore.add(eCent); // add ecent to valid set

		return eCent;
	}

	private static String getSHA256Hash(String passwordToHash) {

		String generatedPassword = null;
		try {
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			String salt = getSalt();
			md.update(salt.getBytes());
			byte[] bytes = md.digest(passwordToHash.getBytes());
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < bytes.length; i++) {
				sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16)
						.substring(1));
			}
			generatedPassword = sb.toString();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return generatedPassword; // return ecent
	}

	private static String getSalt() throws NoSuchAlgorithmException {
		SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
		byte[] salt = new byte[16];
		sr.nextBytes(salt);
		return salt.toString();
	}

}
