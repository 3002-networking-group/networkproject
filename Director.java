import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.net.*;

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

	private HashMap<String, HashMap<String, String>> analystPool; // HashMap<DataType, HashMap<PublicKey, Address>> analyst hashmap pool

	private Set<String> busyAnalyst; // busy analysts (set of public keys)

//	private Set<String> availAnalyst;
	private ConcurrentLinkedQueue<String> availAnalyst;

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

		analystPool = new HashMap<String, HashMap<String, String>>(); // hashmap
		busyAnalyst = Collections.synchronizedSet(new HashSet()); // busy analysts public key

	//	availAnalyst = Collections.synchronizedSet(new HashSet());
		availAnalyst = new ConcurrentLinkedQueue();

		// SSL Certificate
		SSLHandler.declareDualCert("SSL_Certificate", "cits3002");
		ExecutorService executorService = Executors.newFixedThreadPool(100);

		ANNOUNCE("Starting director server");

		// Start Server and listen
		if (this.startSocket(0)) {

			executorService.execute(new DirectorUDP());	// start UDP server to broadcast assigned port and IP

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

				ALERT("WHATS THIS CRAPHERHE");

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
								availAnalyst.add(publicKey);
							}

						} else {
							synchronized(analystPool){
								analystPool.get(type).put(publicKey, address + ":" + port);
								availAnalyst.add(publicKey);
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
						HashMap<String,String> datatype_analysts = analystPool.get(msg_data[DATA_TYPE]);

						boolean stillBusy = true;

						ALERT("HERHEHERHER");
						boolean success = false;

						LinkedList<String> currentPool = new LinkedList();

						synchronized(availAnalyst){
							for(String key : datatype_analysts.keySet()){
								if(availAnalyst.contains(key)){
									currentPool.add(key);			// create pool of availiable analysts
									System.out.println("THIS SI THE KEY: "+key.substring(40,50));
								}
							}
						}

						HashSet tmpBusy = new HashSet();

						HashSet<String> disconnected_analysts = new HashSet();	// temp hashSet of analyst who fail to connect this session
						int numBusy = 0;

						// If there are some analysts
						if (datatype_analysts != null) {
							while (!currentPool.isEmpty()) {

									boolean accepted = false;
									String analystKey = currentPool.poll();

									if(!success){
										ALERT("T---------- THREAD # " + Thread.currentThread().getId() + " LOOPING THROUGH POOL");
										synchronized(availAnalyst){
											if(availAnalyst.contains(analystKey)){
												accepted = true;
												availAnalyst.remove(analystKey);
											} else numBusy++;
										}
									}
									if(accepted){

										ALERT("Analyst Accepted -1-1-1-1-1-1-1-1-1-1-11-");
										if(!success){
											String a = datatype_analysts.get(analystKey);
											analyst = new ServerConnection(a.split(":")[0], Integer.parseInt(a.split(":")[1]));
											ALERT("SERVER CONNECTION CREATED HERHERHEEHREHREHR");

											if(analyst.connected){	// check if analyst is still online

												boolean broken = false;

												try{
													ALERT("Analyst found! Sending Collector the analyst public key...");
													String packet = client.request(MessageFlag.PUB_KEY + ":" + analystKey);
													String data, result = null;

													// Send eCent and data, and request eCent deposit verification
													data = MessageFlag.EXAM_REQ + ":" + packet;

													Message depCon = new Message(analyst.request(data));	// deposit confirmation
													//if(depCon.getFlag().equals(MessageFlag.VALID)) returnable = false;
												//	else
													switch (depCon.getFlagEnum()) {
														case VALID:
															client.send(MessageFlag.VALID);	// ready to recieve data
															break;
														case INVALID:
															broken = true;
															ALERT("Ecent Invalid - Informing Collector");
															client.send(MessageFlag.INVALID);
															stillBusy = false;
															break;
														case DUP:
															broken = true;
															ALERT("Ecent duplicate - Informing Collector");
															client.send(MessageFlag.DUP);
															stillBusy = false;
															break;
														case RET:
															broken = true;
															ALERT("Ecent deposit failed - Returnable Ecent");
															client.send(MessageFlag.RET_CENT);
															stillBusy = false;
															break;
													}
												} catch (IOException err)
												{
													System.out.println("Error with Analyst before Ecent deposited.");
													stillBusy = false;
													availAnalyst.add(analystKey);
													broken = true;
													client.send(MessageFlag.RET_CENT);	// return RET flag to indicate ecent still valid
													break;
												}

												if(!broken){
													try{	// try block AFTER Ecent is deposited
														String result = client.receive();
														analyst.send(result);
														result = analyst.receive();

														client.send(MessageFlag.VALID + ":" + result);

														ALERT("Result returned to Collector");
														success = true;
														stillBusy = false;

														analyst.close();

														availAnalyst.add(analystKey);

													//	synchronized(busyAnalyst){

														//busyAnalyst.remove(analystKey);
														//}

													} catch (IOException err)
													{
														System.out.println("Error with Analyst after Ecent deposited.");
														stillBusy = false;
														client.send(MessageFlag.ERROR);		// return ERROR flag to indicate lost ecent
														break;
													}
												}

											}else{
												System.out.println("Connection failed: " + a + ", trying next one.");
												disconnected_analysts.add(analystKey);
												availAnalyst.remove(analystKey);
												ALERT("ADDING DISCONNECTED ANALYST!?>!?!?!?!??!");
											//	busyAnalyst.remove(analystKey);
											}
										}
									}


								if(!disconnected_analysts.isEmpty()){		// remove disconnected analysts from pool
									ALERT("DELETEING DISCONNECTED ANALYSTS!!_!_!_!_!_!_!_!_!");
								//	synchronized(analystPool)
										for(String s : disconnected_analysts){
											analystPool.get(msg_data[DATA_TYPE]).remove(s);
											availAnalyst.remove(s);
										}
								//
								}
							}
						}else {	// end of if (datatype_analysis != null)
							client.send(MessageFlag.FAIL);	// return fail flag to collector to indicate no analysts
							ALERT("Error: No analysts currently available!");
							stillBusy = false;
							break;
						}
						break;

					//	// end of while
					//	break;	// end of DOIT case

					default:
						ALERT("Unrecognised message: " + msg.raw());
						break;
				}
				client.close();


			} catch (IOException err) {
				ALERT("Closing connection");
				client.close();
			}

		}
	}

	public class DirectorUDP implements Runnable {
		private DatagramSocket socket;

		public DirectorUDP(){
			try{
				socket = new DatagramSocket(0);		// dynammically allocate any port for broadcasting
			}catch (SocketException e){
				ALERT("Could not establish UDP broadcast server");
			}
		}
		public void run(){
			while(true){
				try{
					String tmp = MessageFlag.D_UDP + ":" + getIPAddress() + ";" + director.getLocalPort();
					byte[] message = tmp.getBytes("utf-8");		// encode msg into utf-8 byte array

					InetAddress address = InetAddress.getByName("255.255.255.255");		// get broadcast address

					DatagramPacket packet = new DatagramPacket(message, message.length, address, 1566);	// port 1566 is listening port
					socket.send(packet);

					////////////////// REBROADCAST EVERY X SECONDS ////////////////////
					try{
						//System.out.println("SENT UDP -------------");
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
}
