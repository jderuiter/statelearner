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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

public class VPNTestServiceUDP extends VPNTestService {
	private DatagramSocket socket;
	private static int PACKET_BUFFER_LENGTH =  2048;
    InetAddress remoteInet;
    InetAddress localInet;
    
	public VPNTestServiceUDP() throws Exception {
		super();
		cmd = "";
		SLEEP_CMD = 1000;
		RECEIVE_MSG_TIMEOUT = 100;
		remoteInet = InetAddress.getByName(remote);
		localInet = InetAddress.getByName(local);
		session.setProto("udp");
	}

	/**
	 * Creates an UDP socket bound to the {@link localAddr local address} and {@link localPort local port}
	 * 
	 * @throws UnknownHostException
	 * @throws IOException
	 */
	public void connectSocket() throws UnknownHostException, IOException {
		socket = new DatagramSocket(localPort, localInet);
		socket.setSoTimeout(RECEIVE_MSG_TIMEOUT);
	}

	/**
	 * Close the UDP socket
	 * @throws IOException
	 */
	public void closeSocket() throws IOException {
		if (socket != null) {
			socket.close();
		}
	}

	/**
	 * Return true if the socket is closed
	 * @throws InterruptedException 
	 */
	public boolean connectionClosed() {
		return socket.isClosed();
	}

	/**
	 * Receive a packet and build an output string
	 * @return
	 * @throws Exception
	 */
	public String receiveMessages() throws Exception {
		byte[] buf = new byte[PACKET_BUFFER_LENGTH];
		DatagramPacket p = new DatagramPacket(buf, buf.length);
		List<byte[]> msgList = new ArrayList<byte[]>();

		// Receive the packet
		try {
			while(true) {
				socket.receive(p);
				if(p.getLength() >= PACKET_BUFFER_LENGTH) {
					throw new IOException("UDP-packet buffer too small.");
				}
				msgList.add(Arrays.copyOfRange(p.getData(), p.getOffset(), p.getOffset() + p.getLength()));
			}
		} catch (SocketTimeoutException e) {
			if(!msgList.isEmpty()) {
				String out = session.receiveMessages(msgList);
				if(out.endsWith("ConnectionClosed")) {
					socket.close();
				}
				// ACK the packets received
				sendAck();
				return out;
			} else if (!isServerListening()) {
				// If the server has restarted, then we stop the connection
				socket.close();
				return "ConnectionClosed";
			} else {
				return "Empty";
			}
		}
	}

	public void sendMessage(byte[] msg) throws Exception {
		DatagramPacket p = new DatagramPacket(msg, msg.length, remoteInet, remotePort);
		socket.send(p);
	}
	
	/**
	 * Use the netcap linux command to check if the server is still listening on the UDP port.
	 * If the command returns 1, it means that
	 * an ICMP packet has been sent by the server to indicate an unreachable destination.
	 * It this situation, the client UDP should also be closed.
	 * @return
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public boolean isServerListening() throws IOException, InterruptedException {
		ProcessBuilder builder = new ProcessBuilder("nc","-s",local,"-vu","-w2",remote,Integer.toString(this.remotePort));
		Process process = builder.start();
		BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
		if(reader.readLine() != null) {
			process.destroyForcibly();
			return true;
		}
		boolean ans = process.waitFor() == 0;
		process.destroyForcibly();
		return ans;
	}
}