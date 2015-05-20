import java.io.IOException;
import java.security.*;
import javax.net.ssl.*;
import java.net.*;

import lib.*;

/**
 * Analyst Class for analysing data
 * @author Jesse Fletcher, Caleb Fetzer, Reece Notargiacomo, Alexander Popoff-Asotoff
 * @version 5.9.15
 */

public class Analyst extends Node {

	private ServerConnection bank, director;

	private SSLServerSocket analyst;

	private String analyst_type = "DATA"; // [navigator] or "ORC" [object response coordinator]

	private PrivateKey private_key;
	private PublicKey public_key;

	private boolean bankConn, dirConn;

	private boolean socketIsListening = true;

	private int myPort;

	public static void main(String[] args) {
		load_ip_addresses(args);

		new Analyst();
	}

	public Analyst() {

		dirConn = false;
		bankConn = false;

		set_type("ANALYST-"+analyst_type);
		SSLHandler.declareDualCert("SSL_Certificate","cits3002");

		getServers();
	}

	private void start(){		// start main analyst process

		if(!getKeysFromBank()){
			ANNOUNCE("Could not retrieve Keypair from Bank.");
		}

		if (this.startSocket(0)) {

			if(registerWithDirector())
				ANNOUNCE("Registered!");
			else
				ALERT_WITH_DELAY("Couldn't initialize with Director..");

			while (this.socketIsListening) {
				try {
					SSLSocket clientSocket = (SSLSocket) analyst.accept();
					this.run(clientSocket);

				} catch (IOException err) {
					System.err.println("Error connecting client " + err);
				}
			}
		}
	}

	private void getServers(){	// get bank/dir listening address/port
		while(!bankConn || !dirConn){
			startUDP();
		}
		start();
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

	public boolean startSocket(int portNo) {
		try {
			SSLServerSocketFactory sf;

			sf = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
			analyst = (SSLServerSocket) sf.createServerSocket(portNo);

			myPort = analyst.getLocalPort();

			ANNOUNCE("Analyst started on " + getIPAddress() + ":" + myPort);

			return true;

		} catch (Exception error) {
			System.err.println("Director failed to start: " + error);
			System.exit(-1);

			return false;
		}
	}

	//Get certified encryption/decryption keypair from issuer (bank)
	private boolean getKeysFromBank(){
		ANNOUNCE("Retrieving Keypair from Bank..");

		String keypair_request = MessageFlag.PUB_KEY;
		String response;

		try {
			bank = new ServerConnection(bankIPAddress, bankPort);

			response = bank.request(keypair_request);
			public_key = (PublicKey) KeyFromString(response);

			response = bank.receive();
			private_key = (PrivateKey) PrivateKeyFromString(response);


			bank.close();
		} catch (IOException err) {
			return false;
		}
		if(public_key!=null && private_key!=null) {
			return true;
		}else return false;
	}

	// Send data type to Director
	 // Analyst INIT packet = [ INITFLAG  :  DATA TYPE  ;  ADDRESS  ;  PORT ; PublicKey]
	private boolean registerWithDirector() {
		ANNOUNCE("Registering availability with Director");
		String register_message = MessageFlag.A_INIT + ":" + this.analyst_type+";"+getIPAddress()+";"+Integer.toString(myPort)+";"+StringFromKey(this.public_key);
		String response;
		try {
			director = new ServerConnection(directorIPAddress, dirPort);
			response = director.request(register_message);
			director.close();
		} catch (IOException err) {
			return false;
		}

		return response.equals("REGISTERED");
	}

	private int depositMoney(String eCent) { // return 1 if valid ecent deposited, 0 if it's a duplicate (valid but copy)
	 					//   -1 for invalid ecent hash and 2 for bank connection
		ALERT("Sending eCent to the bank");

		String deposit_request = MessageFlag.BANK_DEP + ":" + eCent;
		Message result;

		try {
			bank = new ServerConnection(bankIPAddress, bankPort);
			result = new Message(bank.request(deposit_request));
			bank.close();
		} catch (IOException err) {
			return 2;	// 2 - error depositing in bank
		}
		switch (result.getFlagEnum()) {
			case VALID:
				return 1;
			case INVALID:
				return -1;
			case DUP:
				return 0;
		}
		return -1;
	}

	private void run(SSLSocket clientSocket) {

			try {
				director =  new ServerConnection(clientSocket);

				Message request = new Message(director.receive());

				ALERT("Receiving request!");

				if(request.getFlag().equals(MessageFlag.EXAM_REQ)) {


					String eCent = decrypt(request.data,private_key);


					if (eCent == null) {
						ALERT("Error: Could not decrypt message! (" + eCent + ")");
					} else {
						// Successful decryption
						ALERT("Depositing payment!");


						//////////////////////SLEEP BLOCK///////////////////////
						try{
							System.out.println("SLEEPING BEFORE DEPOSIT...");
							Thread.sleep(1000);	// 3.5 sec
						}
						catch (Exception e){}
						//////////////////////////////////////////////////////////

						switch(depositMoney(eCent)) {
							case 2:
								director.send(MessageFlag.RET_CENT);
								ALERT_WITH_DELAY("Error depositing to bank.");
								break;
							case 1:
								director.send(MessageFlag.VALID);

								String data = director.receive();

								ALERT("Payment deposited!");

								/////////////////////////SLEEP BLOCK//////////////////////
								try{
									System.out.println("SLEEPING AFTER DEPOSIT...");
									Thread.sleep(1000);	// 3.5 sec
								}
								catch (Exception e){}
								//////////////////////////////////////////////////////////


								String result = performLCS(data); // analyse LCS here

								director.send( result );
								ALERT("Analysis sent!");
								break;
							case -1:
								director.send(MessageFlag.INVALID);
								ALERT("Error: Could not deposit eCent: Invalid Ecent");
								break;
							case 0:
								director.send(MessageFlag.DUP);
								ALERT("Error: Duplicate Ecent.");
								break;
							default:
								break;
						}
					}
				}
				director.close();

			} catch (IOException err) {
				ALERT("Error: Could not recieve message from Director");

			}
	}

	// Perform Longest Common Subsequence algorithm on string

	private String performLCS (String data) {
		String[] parts = data.split("-");
		String pattern = parts[0];
		String randomString = parts[1];

		int M = pattern.length();
		int N = randomString.length();

		// opt[i][j] = length of LCS of x[i..M] and y[j..N]
		int[][] opt = new int[M+1][N+1];

		for (int i = M-1; i >= 0; i--) {
			for (int j = N-1; j >= 0; j--) {
				if (pattern.charAt(i) == randomString.charAt(j))
				opt[i][j] = opt[i+1][j+1] + 1;
				else
				opt[i][j] = Math.max(opt[i+1][j], opt[i][j+1]);
			}
		}

		String lcsString = new String();
		int i = 0, j = 0;

		while(i < M && j < N) {
		if (pattern.charAt(i) == randomString.charAt(j)) {
			// build the LCS
			lcsString += Character.toString(pattern.charAt(i));
			i++;
			j++;
		} else if (opt[i+1][j] >= opt[i][j+1])
			i++;
		else
			j++;
		}
		return lcsString;
	}


}
