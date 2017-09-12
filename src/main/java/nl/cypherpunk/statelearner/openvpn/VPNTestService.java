/*
 *  Copyright (c) 2017 Lesly-Ann Daniel
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package nl.cypherpunk.statelearner.openvpn;

import java.io.File;
import java.io.IOException;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.List;

public abstract class VPNTestService {
	// Network options
	String local  = "172.16.240.1";
	String remote = "172.16.240.128";
	int localPort =  1194;
	int remotePort = 1194;
	
	// Act as a VPN client
	boolean ROLE_CLIENT = true;

	// Restart server after every session
	boolean REQUIRE_RESTART = true;

	// Send output from OpenVPN implementation to console
	boolean CONSOLE_OUTPUT = false;

	// The command line to execute each time we start/reset the SUL
	// For example: to launch the server
	final String CMD_SEPARATOR = ",";
	String cmd;
	
	// Timeouts and delays
	// Time we should wait after executing the command so it have enough time to fully execute
	int SLEEP_CMD;
	// UDP/TCP timeout (ms)
	int RECEIVE_MSG_TIMEOUT;
	
	Process targetProcess;
	VPNSession session;

	public VPNTestService() throws Exception {
		session = new VPNSession();
		session.setInitValues();
	}

	public void setTarget(String target) throws Exception {
		if(target.equals("server")) {
			ROLE_CLIENT = true;
		}
		else if(target.equals("client")) {
			ROLE_CLIENT = false;
		}
		else {
			throw new Exception("Unknown target");
		}
		session.setTarget(target);
	}

	public void setLocal(String local) {
		this.local = local;
	}

	public void setRemote(String remote) {
		this.remote = remote;
	}

	public void setLocalPort(int port) {
		this.localPort = port;
	}

	public void setRemotePort(int port) {
		this.remotePort = port;
	}

	/**
	 * Set the command to restart the OpenVPN server on the VM.
	 * This function only works with a specific architecture.
	 * 
	 * the VM is accessed via ssh,
	 * the old OpenVPN server is killed,
	 * the config file of the server must be in /mnt/hgfs/server/,
	 * the config file must be [version]_[proto]_[method].conf,
	 * the OpenVPN server is started with sudo mode (the VM must be configure to run openvpn in sudo mode without a password).
	 * 
	 * The parameters are only relevant to build the correct config file name.
	 * 
	 * @param version the version of OpenPVN (OpenVPN|OpenVPN-NL)
	 * @param proto the tunneling protocol (UDP|TCP)
	 * @param method the key-method (1|2)
	 */
	public void setCommand(String version, String proto, String method) { 
		cmd = "ssh," + remote + ",sudo killall " + version +
				"; cd /mnt/hgfs/server/; sudo " + version +
				" --config server_" + version + "_" + proto + "_" + method +".conf > OUT";
	}
	
	public void setCommand(String cmd) { 
		this.cmd = cmd;
	}
	
	public void setCipher(String cipher) {
		this.session.setCipher(cipher);
	}
	
	public void setAuth(String auth) {
		this.session.setAuth(auth);
	}
	
	public void setDefault(String version) {
		if(version.equalsIgnoreCase("openvpn-nl")) {
			setCipher("AES-256-CBC");
			setAuth("SHA256");
		} else {
			setCipher("BF-CBC");
			setAuth("SHA1");
		}
	}

	public void setRestartTarget(boolean restart) {
		this.REQUIRE_RESTART = restart;
	}

	public void setReceiveMessagesTimeout(int timeout) {
		this.RECEIVE_MSG_TIMEOUT = timeout;
	}

	public void setConsoleOutput(boolean enable) {
		this.CONSOLE_OUTPUT = enable;
	}

	/**
	 * Start the client and the server.
	 * Open the socket and set the initial values.
	 * @throws Exception
	 */
	public void start() throws Exception {
		if(ROLE_CLIENT) {
			// Starts the server from the command line
			if(cmd != null && !cmd.equals("")) {
				ProcessBuilder pb = new ProcessBuilder(cmd.split(CMD_SEPARATOR));
				if(CONSOLE_OUTPUT) {
					pb.inheritIO();
				} else {
					pb.redirectErrorStream(true);
					pb.redirectOutput(new File("output.log"));
				}
				targetProcess = pb.start();
				Thread.sleep(SLEEP_CMD);
			}

			// Starts the Connection and set the initial values
			connectSocket();
			session.setInitValues();

		} else { // NOT TESTED
			
			//loadServerKey();
			session.setInitValues();

			VPNTestServiceRunnable vpnTestService = this.new VPNTestServiceRunnable(this);
			vpnTestService.start();

			// Starts the client from the command line
			if(cmd != null && !cmd.equals("")) {
				ProcessBuilder pb = new ProcessBuilder(cmd.split(CMD_SEPARATOR));
				if(CONSOLE_OUTPUT) {
					pb.inheritIO();
				} else {
					pb.redirectErrorStream(true);
					pb.redirectOutput(new File("output.log"));
				}
				targetProcess = pb.start();
				//TODO vpnClient = new VPNClient(targetProcess);
			}

			// Wait for the client to send the first message (ClientHello)
			while(!vpnTestService.isReady()) Thread.sleep(10);
		}
	}

	/**
	 * Reset the Connection.
	 * Open the socket and reset the initial values.
	 * @throws Exception
	 */
	public void reset() throws Exception {
		System.out.println("RESET");
		closeSocket();
		session.setInitValues();

		if(ROLE_CLIENT) {
			if(REQUIRE_RESTART && cmd != null && !cmd.equals("")) {
				targetProcess.destroyForcibly();
				targetProcess.waitFor();
				ProcessBuilder pb = new ProcessBuilder(cmd.split(CMD_SEPARATOR));
				if(CONSOLE_OUTPUT) {
					pb.inheritIO();
				} else {
					pb.redirectErrorStream(true);
					pb.redirectOutput(new File("output.log"));
				}
				targetProcess = pb.start();
				Thread.sleep(SLEEP_CMD);
			}
			connectSocket();
		} else { // NOT TESTED
			
			if(targetProcess != null) {
				targetProcess.destroyForcibly();
				targetProcess.waitFor();
			}

			VPNTestServiceRunnable vpnTestService = this.new VPNTestServiceRunnable(this);
			vpnTestService.start();
			Thread.sleep(SLEEP_CMD);

			// Restarts the client
			if(cmd != null && !cmd.equals("")) {
				ProcessBuilder pb = new ProcessBuilder(cmd.split(CMD_SEPARATOR));
				if(CONSOLE_OUTPUT) {
					pb.inheritIO();
				} else {
					pb.redirectErrorStream(true);
					pb.redirectOutput(new File("output.log"));
				}

				targetProcess = pb.start();
				//TODO vpnClient = new VPNClient(targetProcess);
			}

			// Wait for the client to send first message (ClientHello)
			while(!vpnTestService.isReady()) Thread.sleep(10);
		}
	}

	/**
	 * Creates a socket to to communicate with the remote peer
	 * 
	 * @throws UnknownHostException
	 * @throws IOException
	 */
	abstract public void connectSocket() throws UnknownHostException, IOException;

	public void listenSocket() throws UnknownHostException, IOException {
		throw new RuntimeException("Method not implemented yet");
	}

	/**
	 * Close the connexion
	 * @throws IOException
	 */
	abstract public void closeSocket() throws IOException;
	
	/**
	 * Return true if the socket is closed
	 */
	abstract public boolean connectionClosed();

	/**
	 * Receive a packet and build an output string
	 * @return
	 * @throws Exception
	 */
	abstract public String receiveMessages() throws Exception;

	/**
	 * Close the target process
	 * @throws InterruptedException 
	 */
	public void close() throws InterruptedException {
		if(targetProcess != null) {
			targetProcess.destroyForcibly();
			targetProcess.waitFor();
		}
	}

	public String processSymbol(String input) throws Exception {
		String inAction = input;

		if(connectionClosed()) return "ConnectionClosed";

		try {
			if (inAction.equals("CHRv1")) {
				return sendClientHardResetV1();
			}else if (inAction.equals("CHRv2")) {
				return sendClientHardResetV2();
			} else if (inAction.equals("wCHRv1")) {
				return sendWeakCHRV1();
			} else if (inAction.equals("SHRv1")) {
				return sendServerHardResetV1();
			} else if (inAction.equals("SoftReset")) {
				return sendSoftResetV1();
			} else if (inAction.equals("Tls:FullHandshake")) {
				return sendTLSFullHandshake();
			} else if (inAction.equals("TlsInit")) {
				return sendTLSSessionInit();
			} else if (inAction.equals("Tls:ClientHelloAll")) {
				return sendClientHelloAll();
			} else if (inAction.equals("Tls:ClientKeyExchange")) {
				return sendClientKeyExchange();
			} else if (inAction.equals("Tls:ClientCertificate")) {
				return sendClientCertificate();
			} else if (inAction.equals("Tls:ClientCertificateVerify")) {
				return sendClientCertificateVerify();
			} else if (inAction.equals("Tls:ChangeCipherSpec")) {
				return sendChangeCipherSpec();
			} else if (inAction.equals("Tls:Finished")) {
				return sendFinished();
			} else if (inAction.equals("KeyNeg1")) {
				return sendExchangeKeyV1();
			} else if (inAction.equals("KeyNeg2")) {
				return sendExchangeKeyV2();
			} else if (inAction.equals("DataPingReq")) {
				return sendDataV1PingRequest();
			} else if (inAction.equals("CHRa")) {
				return sendClientHardResetA();
			} else if (inAction.equals("CHRb")) {
				return sendClientHardResetB();
			} else if (inAction.equals("CHRc")) {
				return sendClientHardResetC();
			} else if (inAction.equals("TLSa")) {
				return sendTLSSessionInitA();
			} else if (inAction.equals("TLSb")) {
				return sendTLSSessionInitB();
			} else if (inAction.equals("TLSc")) {
				return sendTLSSessionInitC();
			} else {
				System.out.println("Unknown input symbol (" + inAction + ")...");
				System.exit(0);
			}
		}
		catch(SocketException e) {
			String outAction = "ConnectionClosed";
			return outAction;
		}
		return null;
	}

	abstract public void sendMessage(byte[] msg) throws Exception;

	public String sendClientHardResetV1() throws Exception {
		byte[] out = session.buildClientHardResetRand();
		sendMessage(out);
		return receiveMessages();
	}
	
	public String sendClientHardResetV2() throws Exception {
		byte[] out = session.buildClientHardResetV2();
		sendMessage(out);
		return receiveMessages();
	}
	
	public String sendWeakCHRV1() throws Exception {
		byte[] out = session.buildWeakCHRV1();
		sendMessage(out);
		return receiveMessages();
	}
	
	public String sendSoftResetV1() throws Exception {
		byte[] out = session.buildSoftResetV1();
		sendMessage(out);
		return receiveMessages();
	}
	
	public String sendClientHardResetA() throws Exception {
		byte[] out = session.buildClientHardResetSidA();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendClientHardResetB() throws Exception {
		byte[] out = session.buildClientHardResetSidB();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendClientHardResetC() throws Exception {
		byte[] out = session.buildClientHardResetSidC();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendTLSSessionInitA() throws Exception {
		session.setSidA();
		return sendTLSSessionInit();
	}

	public String sendTLSSessionInitB() throws Exception {
		session.setSidB();
		return sendTLSSessionInit();
	}

	public String sendTLSSessionInitC() throws Exception {
		session.setSidC();
		return sendTLSSessionInit();
	}

	public String sendServerHardResetV1() throws Exception {
		byte[] out = session.buildServerHardResetRand();
		sendMessage(out);
		return receiveMessages();
	}

	/**
	 * Acknowledge all the messages in the {@link VPNSession.ackPacketId queue}.
	 * 
	 * @throws Exception
	 */
	public void sendAck() throws Exception {
		List<byte[]> ackList = session.buildAck();
		if (ackList != null) {
			for(byte[] out : ackList) {
				sendMessage(out);
			}
		}
	}

	public String sendClientHelloAll() throws Exception {
		byte[] out = session.buildClientHelloAll();
		sendMessage(out);
		String answer = receiveMessages();
		session.retrieveInitValues();
		return answer;
	}

	/**
	 * Sends all the messages of the TLS handshake;
	 * from the ClientHello to the application message containing the key negociation.
	 * 
	 * @return A string indicating the state of the initialization.
	 * @throws Exception
	 */
	public  String sendTLSSessionInit() throws Exception {
		session.resetTLSSession();
		
		try {
			// Send client Hello
			byte[] out = session.buildClientHelloAll();
			sendMessage(out);
			if(receiveMessages().endsWith("ConnectionClosed")) {
				return "ConnectionClosed";
			}
			session.retrieveInitValues();
			
			// Send the client certificate
			out = session.buildClientCertificate();
			sendMessage(out);
			
			// Send Client Key Exchange
			out = session.buildClientKeyExchange();
			sendMessage(out);
			
			// Send Client certificate Verify
			out = session.buildClientCertificateVerify();
			sendMessage(out);
			
			// Send Change Cipher
			out = session.buildChangeCipherSpec();
			sendMessage(out);
			
			// Send Finished
			out = session.buildFinished();
			sendMessage(out);
			if(receiveMessages().endsWith("ConnectionClosed")) {
				return "ConnectionClosed";
			}
			
			// Proceed to the Key exchange
			out = session.buildExchangeKeyV1();
			sendMessage(out);
			String ans = receiveMessages();
			if(ans.contains("Tls:ApplicationData")) {
				return "Succeed";
			} else if (ans.equals("Ack")) {
				// If the server sends the ACK but the TLS session fails
				// It is because it considers that it is a replay packet
				return "Failed_Ack";
			} else if (ans.endsWith("ConnectionClosed")) {
				return "ConnectionClosed";
			}
			return "Failed_Empty";
		} catch (SocketException e) {
			return "ConnectionClosed";
		}
	}
	
	/**
	 * Sends all the messages of the TLS handshake;
	 * from the ClientHello to the application message containing the key negociation.
	 * 
	 * @return A string indicating the state of the initialization.
	 * @throws Exception
	 */
	public  String sendTLSFullHandshake() throws Exception {
		try {
			byte[] out;
			
			// Send the client certificate
			out = session.buildClientCertificate();
			sendMessage(out);
			
			// Send Client Key Exchange
			out = session.buildClientKeyExchange();
			sendMessage(out);
			
			// Send Client certificate Verify
			out = session.buildClientCertificateVerify();
			sendMessage(out);
			
			// Send Change Cipher
			out = session.buildChangeCipherSpec();
			sendMessage(out);
			
			// Send Finished
			out = session.buildFinished();
			sendMessage(out);
			
			// Gather the response
			return receiveMessages();
		} catch (SocketException e) {
			return "ConnectionClosed";
		}
	}

	public String sendClientHelloRSA() throws Exception {
		byte[] out = session.buildClientHelloRSA();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendClientKeyExchange() throws Exception {
		byte[] out = session.buildClientKeyExchange();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendEmptyCertificate() throws Exception {
		byte[] out = session.buildEmptyCertificate();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendClientCertificate() throws Exception {
		byte[] out = session.buildClientCertificate();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendClientCertificateVerify() throws Exception {
		byte[] out = session.buildClientCertificateVerify();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendChangeCipherSpec() throws Exception {
		byte[] out = session.buildChangeCipherSpec();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendFinished() throws Exception {
		byte[] out = session.buildFinished();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendApplicationData() throws Exception {
		byte[] out = session.buildApplicationData();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendExchangeKeyV1() throws Exception {
		byte[] out = session.buildExchangeKeyV1();
		sendMessage(out);
		return receiveMessages();
	}
	
	public String sendExchangeKeyV2() throws Exception {
		byte[] out = session.buildExchangeKeyV2();
		sendMessage(out);
		return receiveMessages();
	}

	public String sendDataV1PingRequest() throws Exception {
		byte[] out = session.buildDataV1PingRequest();
		sendMessage(out);
		return receiveMessages();
	}

	/**
	 * Test the connection and send messages
	 * @param args 
	 * @throws Exception
	 */
	public static void main(String[] args) throws Exception {
		if(args.length >= 0) {
			VPNTestService vpn = new VPNTestServiceUDP();
			vpn.setTarget("server");
			vpn.setCommand("openvpn", "udp", "1");
			vpn.setDefault("openvpn");
			vpn.cmd = "";

			try {
				vpn.start();
				
				System.out.println(vpn.sendClientHardResetV1());
				System.out.println(vpn.sendTLSSessionInit());
				System.out.println(vpn.sendDataV1PingRequest());
				System.out.println(vpn.sendClientHardResetV1());
				System.out.println(vpn.sendDataV1PingRequest());
				
				//determinismTest(vpn);
				//happyflow2(vpn);
				
				Thread.sleep(1000);
			} catch(SocketException e) {
				e.printStackTrace();
			} finally {
				vpn.closeSocket();
				vpn.close();
			}
			return;
		}
	}

	/**
	 * This method should never terminate if the server is behaving correctly.
	 * Used to catch non-deterministic behavior from the server.
	 * 
	 * @param vpn the vpn session that must be started before the method
	 * @throws Exception
	 */
	public static void determinismTest(VPNTestService vpn) throws Exception {
		// Let us see if the server is deterministic
		String ans = "";
		long loop = 0;
		while(true) {
			++loop;
			
			try {
				vpn.reset();
				ans = vpn.sendWeakCHRV1();
				ans += "_" + vpn.sendClientHelloAll();
				ans += "_" + vpn.sendTLSFullHandshake();
				ans += "_" + vpn.sendExchangeKeyV1();
				
				ans += "_" + vpn.sendSoftResetV1();
				ans += "_" + vpn.sendClientHelloAll();
				// Weird
				ans += "_" + vpn.sendClientHelloAll();
				ans += "_" + vpn.sendWeakCHRV1();
				
				break;
				
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				if (ans.compareTo("SHRv1_Succeed_DataPingRep_SHRv1_Empty") != 0) {
					break;
				}
			}
			System.out.println("Good querry nb: " + loop);
		}

		System.out.println("Querry went wrong after " + loop + " attempts: " + ans);
	}
	
	public static void happyflow1(VPNTestService vpn) throws Exception {
		// Initiate a new TLS Session
		System.out.println("Sending Hard Reset...");
		System.out.println(vpn.sendClientHardResetV1());
		System.out.println("Hard Reset sent\n");

		// Send client Hello
		System.out.println("Sending HelloClient...");
		System.out.println(vpn.sendClientHelloAll());
		//System.out.println(vpn.sendClientHelloRSA());
		System.out.println("HelloAll sent\n");

		// Send the client certificate
		System.out.println("Sending Client certificate...");
		//System.out.print(vpn.sendEmptyCertificate());
		System.out.println(vpn.sendClientCertificate());
		System.out.println("Client Certificate sent\n");

		// Send Client Key Exchange
		System.out.println("Sending Client Key Exchange...");
		System.out.println(vpn.sendClientKeyExchange());
		System.out.println("ClientKeyExchange sent\n");

		// Send Client certificate Verify
		System.out.println("Sending client certificate verify...");
		System.out.println(vpn.sendClientCertificateVerify());
		System.out.println("clientCertificateVerify sent\n");

		// Send Change Cipher
		System.out.println("Sending Change Cipher...");
		System.out.println(vpn.sendChangeCipherSpec());
		System.out.println("Change Cipher sent\n");

		// Send Finished
		System.out.println("Sending finish...");
		System.out.println(vpn.sendFinished());
		System.out.println("Finish sent\n");

		// Send ApplicationData
		System.out.println("Sending KeyExchange...");
		System.out.println(vpn.sendExchangeKeyV1());
		System.out.println("KeyExchange sent\n");

		// Send Ping
		System.out.println("Sending Data...");
		System.out.println(vpn.sendDataV1PingRequest());
		System.out.println("Data sent\n");
		System.out.println("Sending Data...");
		System.out.println(vpn.sendDataV1PingRequest());
		System.out.println("Data sent\n");
		System.out.println("Sending Data...");
		System.out.println(vpn.sendDataV1PingRequest());
		System.out.println("Data sent\n");
		System.out.println("Sending Data...");
		System.out.println(vpn.sendDataV1PingRequest());
		System.out.println("Data sent\n");

		Thread.sleep(1000);
	}

	public static void happyflow2(VPNTestService vpn) throws Exception {
		// Initiate a new TLS Session
		System.out.println("Sending Hard Reset...");
		System.out.println(vpn.sendClientHardResetV2());
		System.out.println("Hard Reset sent\n");

		// Send client Hello
		System.out.println("Sending HelloClient...");
		System.out.println(vpn.sendClientHelloAll());
		//System.out.println(vpn.sendClientHelloRSA());
		System.out.println("HelloAll sent\n");

		// Send the client certificate
		System.out.println("Sending Client certificate...");
		//System.out.print(vpn.sendEmptyCertificate());
		System.out.println(vpn.sendClientCertificate());
		System.out.println("Client Certificate sent\n");

		// Send Client Key Exchange
		System.out.println("Sending Client Key Exchange...");
		System.out.println(vpn.sendClientKeyExchange());
		System.out.println("ClientKeyExchange sent\n");

		// Send Client certificate Verify
		System.out.println("Sending client certificate verify...");
		System.out.println(vpn.sendClientCertificateVerify());
		System.out.println("clientCertificateVerify sent\n");

		// Send Change Cipher
		System.out.println("Sending Change Cipher...");
		System.out.println(vpn.sendChangeCipherSpec());
		System.out.println("Change Cipher sent\n");

		// Send Finished
		System.out.println("Sending finish...");
		System.out.println(vpn.sendFinished());
		System.out.println("Finish sent\n");

		// Send ApplicationData
		System.out.println("Sending KeyExchange...");
		System.out.println(vpn.sendExchangeKeyV2());
		System.out.println("KeyExchange sent\n");

		// Send Ping
		System.out.println("Sending Data...");
		System.out.println(vpn.sendDataV1PingRequest());
		System.out.println("Data sent\n");
		System.out.println("Sending Data...");
		System.out.println(vpn.sendDataV1PingRequest());
		System.out.println("Data sent\n");
		System.out.println("Sending Data...");
		System.out.println(vpn.sendDataV1PingRequest());
		System.out.println("Data sent\n");
		System.out.println("Sending Data...");
		System.out.println(vpn.sendDataV1PingRequest());
		System.out.println("Data sent\n");

		Thread.sleep(1000);
	}

	class VPNTestServiceRunnable extends Thread {
		VPNTestService vpn;
		boolean ready;

		public VPNTestServiceRunnable(VPNTestService vpn) {
			ready = false;
			this.vpn = vpn;
		}

		public boolean isReady() {
			return ready;
		}

		public boolean isConnected() {
			return !vpn.connectionClosed();
		}

		/*public boolean isBound() {
			return  (vpn.socket != null) && vpn.socket.isBound();
		}*/

		public void run() {
			try {
				vpn.listenSocket();
				vpn.receiveMessages();
				ready = true;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
