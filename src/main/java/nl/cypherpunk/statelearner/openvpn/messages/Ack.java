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

package nl.cypherpunk.statelearner.openvpn.messages;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.util.Arrays;

public class Ack {
	byte[] sessionId;         // local session_id (random 64 bit value to identify TLS session)
	//byte[] hmacEncap;       // HMAC signature of entire encapsulation header for HMAC firewall [only if –tls-auth is specified] (usually 16 or 20 bytes)
	//byte[] packetIdRP;      // packet-id for replay protection (4 or 8 bytes, includes sequence number and optional time_t timestamp)
	byte   lengthAckPacketId; // acknowledgment packet-id array length (1 byte).
	byte[] ackPacketId;       // acknowledgment packet-id array (if length > 0).
	byte[] ackRemoteSession;  // acknowledgment remote session-id (if length > 0).

	/**
	 * Create a Ack message from a byte array input stream.
	 * Typically the {@link nl.cypherpunk.statelearner.openvpn.messages.Message#payload playload of a Record}.
	 * 
	 * @param input the ByteArrayInputStream containing the message
	 */
	public Ack(ByteArrayInputStream input) {
		sessionId = new byte[8];
		input.read(sessionId, 0, 8);

		lengthAckPacketId = (byte) input.read();

		if(lengthAckPacketId > 0) {
			ackPacketId = new byte[4];
			input.read(ackPacketId, 0, 4 * lengthAckPacketId);
			ackRemoteSession = new byte[8];
			input.read(ackRemoteSession, 0, 8);
		}
	}

	/**
	 * Create an Ack message
	 * 
	 * @param sessionId the session id of the sender
	 * @param ackPacketId the packets ids to acknowledge 
	 * @param ackRemoteSession the remote session id
	 */
	public Ack(byte[] sessionId, byte[] ackPacketId, byte[] ackRemoteSession) {
		this.sessionId = Arrays.copyOf(sessionId, sessionId.length);
		this.lengthAckPacketId = (byte) (ackPacketId.length / 4);
		this.ackPacketId = Arrays.copyOf(ackPacketId, ackPacketId.length);
		this.ackRemoteSession = Arrays.copyOf(ackRemoteSession, ackRemoteSession.length);
	}

	/**
	 * Return the message as a byte array
	 */
	public byte[] getBytes() {
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		output.write(sessionId, 0, 8);
		output.write(lengthAckPacketId);

		if(lengthAckPacketId > 0) {
			output.write(ackPacketId, 0, 4 * lengthAckPacketId);
			output.write(ackRemoteSession, 0, 8);
		}

		return output.toByteArray();
	}

	public byte[] getSessionId() {
		return this.sessionId;
	}
}
