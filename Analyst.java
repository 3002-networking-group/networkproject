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

	private String analyst_type;

	private PrivateKey private_key;
	private PublicKey public_key;

	private boolean bankConn, dirConn;

	private boolean socketIsListening = true;

	private int myPort;

	public static void main(String[] args) {
		new Analyst(args);
	}

	public Analyst(String[] args) {
		getArgs(args);
		dirConn = false;
		bankConn = false;

		SSLHandler.declareDualCert("SSL_Certificate","cits3002");

		getServers();
	}

	// get arguments
	public void getArgs (String[] args){
		if (args.length==0){
			System.out.println("Please run with analyst parameters:");
			System.out.println("-d starts an analyst in DNA mode");
			System.out.println("-n starts an analyst in Number mode");
			System.out.println("-c starts an analyst in Corrupt mode");
			System.exit(0);
		}

		for(int i=0; i<args.length ; i++){
			if(args[i].equals("-n")){
				analyst_type= "NUM";
				System.out.println("Starting analyst in Number mode");
			}
			else if(args[i].equals("-d")){
				analyst_type= "DNA";
				System.out.println("Starting analyst in DNA mode");
			}
			else if(args[i].equals("-c")){
				analyst_type= "COR";
				System.out.println("Starting analyst in Corrupt mode");
			}

			else{
				System.out.println("Invalid parameter: " +args[i]);
				System.exit(0);
			}

		}

	}

	// start main analyst process
	private void start(){

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

	// get bank/dir listening address/port
	private void getServers(){
		while(!bankConn || !dirConn){
			startUDP();
		}
		start();
	}

	// startUDP listening for bank/director server IP and ports
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
			if(packet.isEmpty()){
				ALERT("UDP: Error listening for Bank/Director address and port...");
			}
			socket.close();
		}catch (SocketException e){
			ALERT("Error creating socket to listen on: Port 1566 in use");
		}catch (IOException e){
			ALERT("Error receiving datagram from UDP server");
		}
	}

	// start SSL socket factory
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

			bank.send(keypair_request);
			response = bank.receive();
			ALERT("KEY PAIR ISSUED - " + response.substring(50,80) );
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

		return response.equals(MessageFlag.VALID);
	}

	private int depositMoney(String eCent) { // return 1 if valid ecent deposited, 0 if it's a duplicate (valid but copy)
	 					//   -1 for invalid ecent hash and 2 for bank connection
		ALERT("Sending eCent to the bank");

		String deposit_request = MessageFlag.BANK_DEP + ":" + eCent;
		Message result;

		try {
			bank = new ServerConnection(bankIPAddress, bankPort);
			String tmp = bank.request(deposit_request);
			result = new Message(tmp);
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
				ALERT("Receiving request! - " + StringFromKey(public_key).substring(50,80));

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
							Thread.sleep(50);
						}
						catch (Exception e){}
						//////////////////////////////////////////////////////////

						switch(depositMoney(eCent)) {
							case 2:
								director.send(MessageFlag.RET_CENT);
								ALERT_WITH_DELAY("Error depositing to bank.");
								director.close();
								break;
							case 1:
								director.send(MessageFlag.VALID);

								String data = director.receive();

								ALERT("Payment deposited!");

								/////////////////////////SLEEP BLOCK//////////////////////
								try{
									System.out.println("SLEEPING AFTER DEPOSIT...");
									Thread.sleep(50);
								}
								catch (Exception e){}
								//////////////////////////////////////////////////////////


								String result = analyse(data); // analyse LCS here

								director.send( result );
								ALERT("Analysis sent!");
								break;
							case -1:
								director.send(MessageFlag.INVALID);
								ALERT("Error: Could not deposit eCent: Invalid Ecent");
								director.close();
								break;
							case 0:
								director.send(MessageFlag.DUP);
								ALERT("Error: Duplicate Ecent.");
								director.close();
								break;
							default:
								break;
						}
					}
				}
				if(director.connected) director.close();

			} catch (IOException err) {
				ALERT("Error: Could not recieve message from Director");
				bankConn = false;
				dirConn = false;
				getServers();
			}
	}

	// check analyst type flags and return correct analysis
	private String analyse(String data){
		if (analyst_type.equals("DNA")){
			return performLCS(data);
		}
		if (analyst_type.equals("NUM")){
			return performNumberAnal(data);
		}
		if (analyst_type.equals("COR")){
			return findCorruption(data);
		}
		return "Analyst failed";
	}

	/////////////////////////////////////////////
	// DATA ANALYSIS METHODS:
	/////////////////////////////////////////////

	private String performNumberAnal(String intString){
		int sum = 0;
		for (int i = 0; i < intString.length(); i++) {
	       		sum += Integer.parseInt(Character.toString(intString.charAt(i)));
		}

		// returns the average represented as a string
		return Integer.toString((sum/intString.length()));
	}
	// Perform Longest Common Subsequence algorithm on string

	private String findCorruption(String corruptedString) {
		// check for an instance of X
		if (corruptedString.indexOf("X") == -1) {
			System.out.println("String is not corrupt! Returning string..");
			return corruptedString;
		} else {
			for (int i = 0; i < corruptedString.length(); i++)
				corruptedString = corruptedString.replace("X","");
			System.out.println("The fixed string is: " + corruptedString);
			return corruptedString;
		}
	 }

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
