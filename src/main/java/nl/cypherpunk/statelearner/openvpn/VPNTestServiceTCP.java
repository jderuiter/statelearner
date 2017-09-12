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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

import nl.cypherpunk.statelearner.tls.Utils;

public class VPNTestServiceTCP extends VPNTestService {
	Socket socket;
	OutputStream output;
	InputStream input;

	public VPNTestServiceTCP() throws Exception {
		super();
		cmd = "";
		SLEEP_CMD = 1000;
		RECEIVE_MSG_TIMEOUT = 800;
		session.setProto("tcp");
	}

	/**
	 * Creates an TCP socket bound to the {@link remote remote address} and {@link remotePort remote port}.
	 * 
	 * @throws UnknownHostException
	 * @throws IOException
	 */
	public void connectSocket() throws UnknownHostException, IOException {
		//InetAddress addr = InetAddress.getByName(this.local);
		//socket = new Socket(this.remote,  this.remotePort, addr, this.localPort);
		socket = new Socket(this.remote, this.remotePort);
		socket.setTcpNoDelay(true);
		socket.setSoTimeout(RECEIVE_MSG_TIMEOUT);
		output = socket.getOutputStream();
		input = socket.getInputStream();
	}

	/**
	 * Close the TCP socket
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
		List<byte[]> msgList = new ArrayList<byte[]>();
		byte[] length = new byte[2];
		
		try {
			length[0] = (byte)input.read();
		} catch (SocketTimeoutException e) {
			return "Empty";
		}
		if(length[0] == -1) {
			// We got to the end of the stream
			return "ConnectionClosed";
		}
		length[1] = (byte)input.read();

		while(input.available() > 0) {
			int len = Utils.getuint16(length[0], length[1]);

			// Create the Message
			byte[] msg = new byte[len];
			input.read(msg);
			msgList.add(msg);

			try {
				length[0] = (byte)input.read();
			} catch (SocketTimeoutException e) {
				break;
			}

			if(length[0] == -1) {
				break;
			}
			
			length[1] = (byte)input.read();
		}
		
		if(!msgList.isEmpty()) {
			String out = session.receiveMessages(msgList);
			if(length[0] == -1) {
				out += "ConnectionClosed";
			}
			if(out.endsWith("ConnectionClosed")) {
				socket.close();
			}
			// ACK the packets received
			sendAck();
			return out;
		} else {
			return "Empty";
		}
	}

	public void sendMessage(byte[] msg) throws Exception {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(Utils.getbytes16(msg.length));
		out.write(msg);
		output.write(out.toByteArray());
	}
}
