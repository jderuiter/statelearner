/*
 *  Copyright (c) 2016 Joeri de Ruiter
 *  Modifications copyright (C) 2017 Lesly-Ann Daniel
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

package nl.cypherpunk.statelearner.tls;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class TLSTestService {
	Socket socket;
	OutputStream output;
	InputStream input;

	String host = "127.0.0.1";
	int port = 4433;

	// Act as a TLS client
	boolean ROLE_CLIENT = true;
	// Restart server after every session
	boolean REQUIRE_RESTART = false;
	// Timeout in ms
	int RECEIVE_MSG_TIMEOUT = 100;
	// Send output from TLS implementation to console
	boolean CONSOLE_OUTPUT = false;

	String cmd;
	Process targetProcess;
	TLSClient tlsClient;

	TLSSession tlsSession;	

	public static TLSTestService createTLSServerTestService(String cmd, int port, boolean restart) throws Exception {
		TLSTestService service = new TLSTestService();
		service.setTarget("server");
		service.setCommand(cmd);
		service.setPort(port);
		service.setRestartTarget(restart);
		service.start();
		return service;
	}

	public static TLSTestService createTLSClientTestService(String cmd, String host, int port) throws Exception {
		TLSTestService service = new TLSTestService();
		service.setTarget("client");
		service.setCommand(cmd);
		service.setHost(host);
		service.setPort(port);
		service.start();

		return service;
	}

	public TLSTestService() throws Exception {
		tlsSession = new TLSSession();
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
		tlsSession.setTarget(target);
	}

	public void setHost(String host) {
		this.host = host;
	}

	public void setPort(int port) {
		this.port = port;
	}

	public void setCommand(String cmd) {
		this.cmd = cmd;
	}

	public void setRestartTarget(boolean restart) {
		this.REQUIRE_RESTART = restart;
	}

	public void setReceiveMessagesTimeout(int timeout) {
		RECEIVE_MSG_TIMEOUT = timeout;
	}

	public void setConsoleOutput(boolean enable) {
		CONSOLE_OUTPUT = enable;
	}

	public void setKeystore(String filename, String password) {
		tlsSession.setKeystore(filename, password);
	}
	
	public void useTLS10() {
		tlsSession.useTLS10();
	}
	
	public void useTLS12() {
		tlsSession.useTLS12();
	}

	public void start() throws Exception {
		if(ROLE_CLIENT) {
			tlsSession.loadClientKey();

			if(cmd != null && !cmd.equals("")) {
				ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));

				if(CONSOLE_OUTPUT) {
					pb.inheritIO();
				}
				else {
					pb.redirectErrorStream(true);
					pb.redirectOutput(new File("output.log"));
				}

				targetProcess = pb.start();


				Thread.sleep(5000);
			}

			connectSocket();

			retrieveInitValues();
			tlsSession.setInitValues();
		}
		else {
			tlsSession.loadServerKey();
			tlsSession.setInitValues();

			TLSTestServiceRunnable tlsTestService = this.new TLSTestServiceRunnable(this);
			tlsTestService.start();

			if(cmd != null && !cmd.equals("")) {
				ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));

				if(CONSOLE_OUTPUT) {
					pb.inheritIO();
				}
				else {
					pb.redirectErrorStream(true);
					pb.redirectOutput(new File("output.log"));
				}

				targetProcess = pb.start();
				tlsClient = new TLSClient(targetProcess);
			}

			// Wait for the client to send the first message (ClientHello)
			while(!tlsTestService.isReady()) Thread.sleep(10);
		}
	}

	public void reset() throws Exception {
		//System.out.println("RESET");
		socket.close();
		tlsSession.setInitValues();

		if(ROLE_CLIENT) {
			if(REQUIRE_RESTART && cmd != null && !cmd.equals("")) {
				targetProcess.destroy();

				Thread.sleep(500);

				ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));

				if(CONSOLE_OUTPUT) {
					pb.inheritIO();
				} else {
					pb.redirectErrorStream(true);
					pb.redirectOutput(new File("output.log"));
				}

				targetProcess = pb.start();

				Thread.sleep(200);
			}

			connectSocket();

			tlsSession.reset();
		} else {
			if(targetProcess != null) {
				targetProcess.destroy();
			}

			TLSTestServiceRunnable tlsTestService = this.new TLSTestServiceRunnable(this);
			tlsTestService.start();
			Thread.sleep(100);

			if(cmd != null && !cmd.equals("")) {
				ProcessBuilder pb = new ProcessBuilder(cmd.split(" "));

				if(CONSOLE_OUTPUT) {
					pb.inheritIO();
				} else {
					pb.redirectErrorStream(true);
					pb.redirectOutput(new File("output.log"));
				}

				targetProcess = pb.start();
				tlsClient = new TLSClient(targetProcess);
			}

			// Wait for the client to send first message (ClientHello)
			while(!tlsTestService.isReady()) Thread.sleep(10);
		}
	}

	public void connectSocket() throws UnknownHostException, IOException {
		socket = new Socket(host, port);
		socket.setTcpNoDelay(true);
		socket.setSoTimeout(RECEIVE_MSG_TIMEOUT);

		output = socket.getOutputStream();
		input = socket.getInputStream();
	}

	public void listenSocket() throws UnknownHostException, IOException {
		ServerSocket server = new ServerSocket();
		server.bind(new InetSocketAddress(host, port));
		socket = server.accept();
		socket.setTcpNoDelay(true);
		socket.setSoTimeout(RECEIVE_MSG_TIMEOUT);

		output = socket.getOutputStream();
		input = socket.getInputStream();

		server.close();
	}

	public void closeSocket() throws IOException {
		socket.close();
	}

	public void retrieveInitValues() throws Exception {
		sendMessage(tlsSession.buildClientHelloAll());

		tlsSession.retrieveInitValues();

		if(REQUIRE_RESTART) {
			reset();
		} else {
			socket.close();
			connectSocket();
		}
	}

	public String receiveMessages() throws Exception {
		String out = tlsSession.receiveMessages(input);
		if(out.compareTo("ConnectionClosed") == 0) {
			socket.close();
		}
		return out;
	}

	void sendMessage(byte[] msg) throws Exception {
		output.write(msg);
	}

	public void close() {
		if(targetProcess != null) {
			targetProcess.destroy();
		}
	}

	public String processSymbol(String input) throws Exception {
		String inAction = input;
		byte[] out = null;

		if(!socket.isConnected() || socket.isClosed()) return "ConnectionClosed";

		try {
			if (inAction.equals("ClientHello")) {
				out = tlsSession.buildClientHelloAll();
			} else if (inAction.equals("ClientHelloDHE")) {
				out = tlsSession.buildClientHelloDHE();
			} else if (inAction.equals("ClientHelloRSA")) {
				out = tlsSession.buildClientHelloRSA();
			} else if (inAction.equals("ClientHelloDHEReset")) {
				out = tlsSession.buildClientHelloDHEReset();
			} else if (inAction.equals("ClientHelloRSAReset")) {
				out = tlsSession.buildClientHelloRSAReset();
			} else if (inAction.equals("ServerHelloRSA")) {
				out = tlsSession.buildServerHelloRSA();
			} else if (inAction.equals("ServerHelloDHE")) {
				out = tlsSession.buildServerHelloDHE();
			} else if (inAction.equals("EmptyCertificate")) {
				out = tlsSession.buildEmptyCertificate();
			} else if (inAction.equals("ServerCertificate")) {
				out = tlsSession.buildServerCertificate();
			} else if (inAction.equals("ServerKeyExchange")) {
				out = tlsSession.buildServerKeyExchange();
			} else if (inAction.equals("CertificateRequest")) {
				out = tlsSession.buildCertificateRequest();
			} else if (inAction.equals("ServerHelloDone")) {
				out = tlsSession.buildServerHelloDone();
			} else if (inAction.equals("ClientCertificate")) {
				out = tlsSession.buildClientCertificate();
			} else if (inAction.equals("ClientCertificateVerify")) {
				out = tlsSession.buildClientCertificateVerify();
			} else if (inAction.equals("ClientKeyExchange")) {
				out = tlsSession.buildClientKeyExchange();
			} else if (inAction.equals("ChangeCipherSpec")) {
				out = tlsSession.buildChangeCipherSpec();
			} else if (inAction.equals("Finished")) {
				out = tlsSession.buildFinished();
			} else if (inAction.equals("ApplicationData")) {
				out = tlsSession.buildApplicationData();
			} else if (inAction.equals("ApplicationDataEmpty")) {
				out = tlsSession.buildApplicationDataEmpty();
			} else if (inAction.equals("HeartbeatRequest")) {
				out = tlsSession.buildHeartbeatRequest();
			} else if (inAction.equals("HeartbeatResponse")) {
				out = tlsSession.buildHeartbeatResponse();
			} else if (inAction.equals("Alert10")) {
				out = tlsSession.buildAlert10();
			} else if (inAction.equals("Alert1100")) {
				out = tlsSession.buildAlert1100();
			} else {
				System.out.println("Unknown input symbol (" + inAction + ")...");
				System.exit(0);
			}
			sendMessage(out);
			return receiveMessages();
		}
		catch(SocketException e) {
			//String outAction = "ConnectionClosedException";
			String outAction = "ConnectionClosed";

			return outAction;
		}
	}

	public static void main(String[] args) throws Exception {
		if(args.length >= 0) {
			TLSTestService tls = new TLSTestService();
			tls.setTarget("server");
			tls.setHost("localhost");
			tls.setPort(4433);
			//tls.setCommand("openssl s_server -key server.key -cert server.crt -CAfile cacert.pem -accept 4433 -HTTP");
			tls.setReceiveMessagesTimeout(100);
			tls.setConsoleOutput(true);

			tls.start();

			tls.useTLS10();

			try {
				System.out.print("SendClientHello = " + tls.processSymbol("ClientHello"));
				//System.out.println("ClientHelloDHE: " + tls.processSymbol("ClientHelloDHE"));

				/*if(args.length >= 3 && args[2].equals("1")) {
					System.out.print(" " + tls.processSymbol("EmptyCertificate"));
					System.out.println("ClientCertificate: " + tls.processSymbol("ClientCertificate"));
				}*/

				//System.out.println(" " + tls.processSymbol("ClientCertificate());
				System.out.println("SendClientKeyExchange = " + tls.processSymbol("ClientKeyExchange"));
				//System.out.println(" " + tls.processSymbol("ClientCertificateVerify"));
				System.out.println("SendChangeCipherSpec = " + tls.processSymbol("ChangeCipherSpec"));
				System.out.println("SendFinished = " + tls.processSymbol("Finished"));
				System.out.println("SendApplicationData = " + tls.processSymbol("ApplicationData"));
			}
			catch(SocketException e) {
				e.printStackTrace();
				System.out.println(" ConnectionClosed");
			}

			tls.closeSocket();
			tls.close();
			return;
		}
	}

	class TLSTestServiceRunnable extends Thread {
		TLSTestService tls;
		boolean ready;

		public TLSTestServiceRunnable(TLSTestService tls) {
			ready = false;
			this.tls = tls;
		}

		public boolean isReady() {
			return ready;
		}

		public boolean isConnected() {
			return tls.socket.isConnected();
		}

		public boolean isBound() {
			return  (tls.socket != null) && tls.socket.isBound();
		}

		public void run() {
			try {
				tls.listenSocket();
				tls.receiveMessages();
				ready = true;
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}
}
