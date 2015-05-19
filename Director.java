import java.io.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.*;

import javax.net.ssl.*;

import lib.*;

/**
 * Director Node class
 *
 * @author Jesse Fletcher, Caleb Fetzer, Reece Notargiacomo, Alexaner
 *         Popoff-Asotoff
 * @version 5.9.15
 *
 */
public class Director extends Node {

	private static int PORT = 9998;
	private SSLServerSocket director;
	private ServerConnection analyst;

	private static final int DATA_TYPE = 0;
	private static final int PUBLIC_KEY = 1;

	private Map<String, HashMap<String, String>> analystPool; // HashMap<DataType, HashMap<PublicKey, Address>> analyst hashmap pool

	private Set<String> busyAnalyst; // busy analysts (set of public keys)

	private boolean socketIsListening = true;

	// main
	public static void main(String[] args) {
		int newPort = PORT;

		// Option to give the port as an argument
		if (args.length == 1)
			try {
				newPort = Integer.valueOf(args[0], 10);
			} catch (NumberFormatException er) {
				newPort = PORT;
			}

		new Director(newPort);
	}

	// constructor
	public Director(int portNo) {
		set_type("DIRECTOR");

		analystPool = Collections.synchronizedMap(new HashMap<String, HashMap<String, String>>()); // hashmap
		busyAnalyst = Collections.synchronizedSet(new HashSet<String>()); // busy analysts public key

		// SSL Certificate
		SSLHandler.declareDualCert("SSL_Certificate", "cits3002");
		ExecutorService executorService = Executors.newFixedThreadPool(100);

		ANNOUNCE("Starting director server");

		// Start Server and listen
		if (this.startSocket(portNo)) {

			while (this.socketIsListening) {
				try {
					SSLSocket clientSocket = (SSLSocket) director.accept();
					executorService.execute(new DirectorClient(clientSocket));

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
			director = (SSLServerSocket) sf.createServerSocket(portNo);

			ANNOUNCE("Director started on " + getIPAddress() + ":" + portNo);

			return true;

		} catch (Exception error) {
			System.err.println("Director failed to start: " + error);
			System.exit(-1);

			return false;
		}
	}

	public class DirectorClient implements Runnable {

		protected ServerConnection client;

		public DirectorClient(SSLSocket socket) {
			client = new ServerConnection(socket);
		}

		public void run() {
			try {
				Message msg = new Message(client.receive());
				String[] msg_data = msg.getData();

				switch (msg.getFlagEnum()) {

					/*
					 * C_INIT
					 * Initiate collector
					 * C_INIT => INIC
					 */
					case INIC:
						// Collector connecting
						ALERT("Collector connected...");
						String data_type_available = "" + analystPool.containsKey(msg.data);
						client.send(data_type_available);
						client.close();
						break;

					/*
					 * A_INIT
					 * Initiate analyst
					 * A_INIT => INIA
					 */
					// Analyst INIT packet = [ INITFLAG  :  DATA TYPE  ;  ADDRESS  ;  PORT ; PublicKey]
					case INIA:
						String type = msg.data.split(";")[0];
						String address = msg.data.split(";")[1];
						String port = msg.data.split(";")[2];
						String publicKey = msg.data.split(";")[3];

						if (!analystPool.containsKey(type)) {

							HashMap<String, String> newpool = new HashMap<String, String>();

							synchronized(analystPool){
								newpool.put(publicKey, address + ":" + port);
								analystPool.put(type, newpool);
							}

						} else {
							synchronized(analystPool){
								analystPool.get(type).put(publicKey, address + ":" + port);
							}
						}

						ALERT("Analyst connected... (" + type + ")");

						client.send("REGISTERED");
						break;	// end of analyst init case

					/*
					 * EXAM_REQ:
					 * Data analysis request
					 * EXAM_REQ => DOIT
					 */
					case DOIT:
						ALERT("Collector sending request...");
						ALERT("Data Analysis request recieved");
						boolean success = false;
						boolean stillBusy = true;

						while(stillBusy){	// while theres still busy analysts left
							synchronized(analystPool){	// lock analyst pool
								synchronized(busyAnalyst){

								HashMap<String,String> datatype_analysts = analystPool.get(msg_data[DATA_TYPE]);

								// Get list of analysts for this data type

								HashSet<String> disconnected_analysts = new HashSet();	// temp hashSet of analyst who fail to connect this session
								int numBusy = 0;

								// If there are some analysts
								if (datatype_analysts != null) {

									// Try some analyst until you find one that's free and connected
									for (String analystKey : datatype_analysts.keySet()) {

										if (!busyAnalyst.contains(analystKey) && !success) {
											String a = datatype_analysts.get(analystKey);

											analyst = new ServerConnection(a.split(":")[0], Integer.parseInt(a.split(":")[1]));

											if(analyst.connected){

												try{	// try block BEFORE the ecent is deposited
													//
														// Reserve the analyst and lock busyAnalyst set
														busyAnalyst.add(analystKey);


													ALERT("Analyst found! Sending Collector the analyst public key...");
													String packet = client.request(MessageFlag.PUB_KEY + ":" + analystKey);
													String data, result = null;

													// Send eCent and data, and request eCent deposit verification
													data = MessageFlag.EXAM_REQ + ":" + packet;
													boolean returnable = true;

													Message depCon = new Message(analyst.request(data));	// deposit confirmation
													if(depCon.getFlag().equals(MessageFlag.VALID)) returnable = false;
													else{
														switch (depCon.getFlagEnum()) {
															case INVALID:
																ALERT("Ecent Invalid - Informing Collector");
																client.send(MessageFlag.INVALID);
																break;
															case DUP:
																ALERT("Ecent duplicate - Informing Collector");
																client.send(MessageFlag.DUP);
																break;
															case RET:
																ALERT("Ecent deposit failed - Returnable Ecent");
																client.send(MessageFlag.RET_CENT);
																break;
														}
														break;	// break loop (bad ecent)
													}

												} catch (IOException err)
												{
													System.out.println("Error with Analyst before Ecent deposited.");
													client.send(MessageFlag.RET_CENT);	// return RET flag to indicate ecent still valid
													break;
												}

												try{	// try block AFTER Ecent is deposited
													String result = analyst.receive();
													ALERT("Result recieved from Analyst");

													client.send(MessageFlag.VALID + ":" + result);

													ALERT("Result returned to Collector");
													ALERT("i love balls");
													success = true;
													stillBusy = false;

													//synchronized(busyAnalyst){
														busyAnalyst.remove(analystKey);
													//}

												} catch (IOException err)
												{
													System.out.println("Error with Analyst after Ecent deposited.");
													client.send(MessageFlag.ERROR);		// return ERROR flag to indicate lost ecent
													break;
												}

											}else{
												System.out.println("Connection failed: " + a + ", trying next one.");
												disconnected_analysts.add(analystKey);
											}

										}else numBusy++;	// count analyst as busy (as opposed to dc)
									}

									if(numBusy==0 || success) stillBusy = false;	// no busy analysts left or success = break while loop

									if(!disconnected_analysts.isEmpty()){		// remove disconnected analysts from pool
											for(String s : disconnected_analysts){
												analystPool.get(msg_data[DATA_TYPE]).remove(s);
											}
									}
								}
								}
							}
						}
						if (success) {
							ALERT("Finished analysis!");
						}else {
							client.send(MessageFlag.FAIL);	// return fail flag to collector to indicate no analysts
							ALERT("Error: No analysts currently available!");
						}
						break;	// end of DOIT case

					default:
						ALERT("Unrecognised message: " + msg.raw());
						break;
				}

				client.close();

			} catch(IOException err) {
				ALERT("Closing connection");
				client.close();

			}

		}
	}

}
