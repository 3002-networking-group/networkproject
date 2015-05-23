import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.net.*;
import java.lang.*;

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

	private static int PORT = 2104;
	private SSLServerSocket director;

	private static final int DATA_TYPE = 0;

	private HashMap<String, HashMap<String, String>> analystPool; // HashMap<DataType, HashMap<PublicKey, Address>> analyst hashmap pool

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

		analystPool = new HashMap<String, HashMap<String, String>>(); // hashmap

	//	availAnalyst = Collections.synchronizedSet(new HashSet());
		availAnalyst = new ConcurrentLinkedQueue<String>();

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

		protected final ServerConnection client;

		public DirectorClient(SSLSocket socket) {
			client =  new ServerConnection(socket);

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
						ALERT(" THREAD # " + Thread.currentThread().getId() + "\t COLLECTOR INITIATED");
						if(analystPool.containsKey(msg.data)){
							client.send(MessageFlag.VALID);		// VALID For analyst data type availiable
						}else{
							client.send(MessageFlag.FAIL);		// FAIL for no analysts availiable
						}
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

						ALERT("THREAD#" + Thread.currentThread().getId() + "\t ANALYST CONNECTED \t" + publicKey.substring(50,80));

						client.send(MessageFlag.VALID);
						break;	// end of analyst init case

					/*
					 * EXAM_REQ:
					 * Data analysis request
					 * EXAM_REQ => DOIT
					 */
					case DOIT:

						HashMap<String,String> datatype_analysts = analystPool.get(msg_data[DATA_TYPE]);
						if (!datatype_analysts.isEmpty()) {// If there are some analysts
							boolean stillBusy = true;
							int numBusy = 0;

							while(stillBusy){

								boolean success = false;
								LinkedList<String> currentPool = new LinkedList();
							//	synchronized(availAnalyst){
									for(String key : datatype_analysts.keySet()){
										if(availAnalyst.contains(key)){
											String tmp = key;
											currentPool.add(tmp);			// create pool of availiable analysts
											ALERT(" THREAD # " + Thread.currentThread().getId() + "\t LOOPING THROUGH POOL - key \t" + tmp.substring(50,80));
										}
									}
						//		}
								HashSet<String> disconnected_analysts = new HashSet<String>();	// temp hashSet of analyst who fail to connect this session


								while (!currentPool.isEmpty() && !success) {

										boolean accepted = false;
										String analystKey = currentPool.poll();
										ALERT(" THREAD # " + Thread.currentThread().getId() + "\t LOOPING THROUGH POOL - key \t" + analystKey.substring(50,80));
										if(!success){
											//synchronized(availAnalyst){
												if(availAnalyst.contains(analystKey)){
													accepted = true;
													availAnalyst.remove(analystKey);
													ALERT(" THREAD # " + Thread.currentThread().getId() + "\t ANALYST REMOVED FROM POOL \t" + analystKey.substring(50,80));
												} else numBusy++;
											//}
										}
										if(accepted){
											ALERT(" THREAD # " + Thread.currentThread().getId() + " \t ANALYST ACCEPTED AS AVAIL.\t" + analystKey.substring(50,80));
											if(!success){
												String a = datatype_analysts.get(analystKey);
												ServerConnection analyst = new ServerConnection(a.split(":")[0], Integer.parseInt(a.split(":")[1]));
												ALERT(" THREAD # " + Thread.currentThread().getId() + "\t ANALYST CONNECTION CREATED \t" + analystKey.substring(50,80));

												if(analyst.connected){	// check if analyst is still online
													boolean broken = false;
													try{
														ALERT(" THREAD # " + Thread.currentThread().getId() + "\t SENDING COLLECTOR PUBLIC KEY\t" + analystKey.substring(50,80));
														String packet = client.request(MessageFlag.PUB_KEY + ":" + analystKey);
														String data, result = null;

														// Send eCent and data, and request eCent deposit verification
														data = MessageFlag.EXAM_REQ + ":" + packet;

														Message depCon = new Message(analyst.request(data));	// deposit confirmation
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
														ALERT(" THREAD # " + Thread.currentThread().getId() + "!!!!!!!!!!!ERROR W/ ANALYST BEF DEPOSIT \t" + analystKey.substring(50,80));
														stillBusy = false;
														availAnalyst.add(analystKey);
														broken = true;
														client.send(MessageFlag.RET_CENT);	// return RET flag to indicate ecent still valid
														disconnected_analysts.add(analystKey);
														break;
													}

													if(!broken){	// If Ecent deposited successfully
														try{	// try block AFTER Ecent is deposited
															String result = client.receive();
															analyst.send(result);
															result = analyst.receive();

															client.send(MessageFlag.VALID + ":" + result);

															ALERT(" THREAD # " + Thread.currentThread().getId() + "\t RESULT RETURNED TO COLLECTOR \t" + analystKey.substring(50,80));
															success = true;
															stillBusy = false;

															analyst.close();

															ALERT(" THREAD # " + Thread.currentThread().getId() + "\t ADDING ANALYST TO AVAILIABLE \t" + analystKey.substring(50,80));
															availAnalyst.add(analystKey);


														} catch (IOException err)
														{
															ALERT(" THREAD # " + Thread.currentThread().getId() + "!!!!!!!!!!!ERROR W/ ANALYST AFT DEPOSIT \t" + analystKey.substring(50,80));
															stillBusy = false;
															this.client.send(MessageFlag.ERROR);		// return ERROR flag to indicate lost ecent
															analyst.close();
															disconnected_analysts.add(analystKey);
															client.close();
															break;
														}
													}else{
														client.close();
														analyst.close();
														availAnalyst.add(analystKey);
													}

												}else{  // if analyst not connected
													disconnected_analysts.add(analystKey);
													ALERT(" THREAD # " + Thread.currentThread().getId() + "!!!!!!!!!!!ADDING DISCONNECTED ANALYST \t" + analystKey.substring(50,80));
												}
											}
										} // end of if(accepted)


									if(!disconnected_analysts.isEmpty()){		// remove disconnected analysts from pool
									//	synchronized(availAnalyst){
											for(String s : disconnected_analysts){
												analystPool.get(msg_data[DATA_TYPE]).remove(s);
												availAnalyst.remove(s);
												ALERT(" THREAD # " + Thread.currentThread().getId() + "!!!!!!!!!!!DELETEING DISCONNECTED ANALYSTS!!");
											}
									//	}
									}
								} // end of while(!currentPool.isEmpty && !success)
								if(numBusy==0) stillBusy = false;
							} // end of while(stillBusy)

						}else {	// end of if (!datatype_analysis.isEmpty())
							client.send(MessageFlag.FAIL);	// return fail flag to collector to indicate no analysts
							ALERT(" THREAD # " + Thread.currentThread().getId() + "!!!!!!!!!!!NO ANALYSTS CURRENTLY AVAILIABLE!!!!!!");
							break;
						}
						break;

					//
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
