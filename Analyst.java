import java.io.IOException;
import java.security.*;
import javax.net.ssl.*;

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

	private boolean socketIsListening = true;

	private int myPort;

	public static void main(String[] args) {
		load_ip_addresses(args);

		new Analyst();
	}

	public Analyst() {
		set_type("ANALYST-"+analyst_type);
		SSLHandler.declareDualCert("SSL_Certificate","cits3002");
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

					String decrypted_packet = decrypt(request.data,private_key);

					if (decrypted_packet == null) {
						ALERT("Error: Could not decrypt message! (" + decrypted_packet + ")");
					} else {
						// Successful decryption
						ALERT("Depositing payment!");

						String eCent = decrypted_packet.split(":")[0];
						String data = decrypted_packet.split(":")[1];

						//////////////////////SLEEP BLOCK///////////////////////
						try{
							System.out.println("SLEEPING BEFORE DEPOSIT...");
							Thread.sleep(3500);	// 3.5 sec
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

								ALERT("Payment deposited!");

								/////////////////////////SLEEP BLOCK//////////////////////
								try{
									System.out.println("SLEEPING AFTER DEPOSIT...");
									Thread.sleep(3500);	// 3.5 sec
								}
								catch (Exception e){}
								//////////////////////////////////////////////////////////

								String result = data + "good"; // analyse LCS here

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
						}
					}
				}
				director.close();

			} catch (IOException err) {
				ALERT("Error: Could not recieve message from Director");

			}

		}


}
