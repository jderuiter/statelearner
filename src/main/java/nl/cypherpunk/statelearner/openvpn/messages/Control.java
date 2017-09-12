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

public abstract class Control {
		// Control channel message
		private byte[] sessionId;         // local session_id (random 64 bit value to identify TLS session)
		//private byte[] hmacEncap;       // HMAC signature of entire encapsulation header for HMAC firewall
			                                  // [only if –tls-auth is specified] (usually 16 or 20 bytes)
		//byte[] packetIdRP;              // packet-id for replay protection (4 or 8 bytes,
			                                  // includes sequence number and optional time_t timestamp)
		private byte   lengthAckPacketId; // acknowledgment packet-id array length (1 byte).
		private byte[] ackPacketId;       // acknowledgment packet-id array (if length > 0).
		private byte[] ackRemoteSession;  // acknowledgment remote session-id (if length > 0).
		private byte[] packetId;          // packet-id of this message (4 bytes).
		
		/**
		 * Generates a new HardResetV1 message from a randomly generated TSL session identifier
		 * @param sessionId the TSL session identidier
		 */
		public Control(byte[] sessionId, byte[] packetId) {
			this.sessionId = Arrays.copyOf(sessionId, sessionId.length);
			this.lengthAckPacketId = 0;
			this.packetId = Arrays.copyOf(packetId, packetId.length);
		}
		
		/**
		 * Create a HardResetV1 message from a byte array input stream.
		 * Typically the {@link nl.cypherpunk.statelearner.openvpn.messages.Message#payload playload of a Record}.
		 * @param input the ByteArrayInputStream containing the message
		 */
		public Control(ByteArrayInputStream input) {
			sessionId = new byte[Message.SID_SIZE];
			input.read(sessionId, 0, 8);
			
			lengthAckPacketId = (byte) input.read();
			
			if(lengthAckPacketId > 0) {
				ackPacketId = new byte[4 * lengthAckPacketId];
				input.read(ackPacketId, 0, 4 * lengthAckPacketId);
				ackRemoteSession = new byte[Message.SID_SIZE];
				input.read(ackRemoteSession, 0, 8);
			}
			
			packetId = new byte[4];
			input.read(packetId, 0, 4);
		}
		
		public byte[] getSessionId() {
			return sessionId;
		}

		public void setSessionId(byte[] sessionId) {
			this.sessionId = sessionId;
		}

		public byte getLengthAckPacketId() {
			return lengthAckPacketId;
		}

		public void setLengthAckPacketId(byte lengthAckPacketId) {
			this.lengthAckPacketId = lengthAckPacketId;
		}

		public byte[] getAckPacketId() {
			return ackPacketId;
		}

		public void setAckPacketId(byte[] ackPacketId) {
			this.ackPacketId = ackPacketId;
		}

		public byte[] getAckRemoteSession() {
			return ackRemoteSession;
		}

		public void setAckRemoteSession(byte[] ackRemoteSession) {
			this.ackRemoteSession = ackRemoteSession;
		}

		public byte[] getPacketId() {
			return packetId;
		}

		public void setPacketId(byte[] packetId) {
			this.packetId = packetId;
		}
		
		/**
		 * Return the message as a byte array
		 */
		public byte[] getBytes() {
			return getOutputStream().toByteArray();
		}
		
		/**
		 * Return the message as a {@link ByteArrayOutputStream}
		 */
		protected ByteArrayOutputStream getOutputStream() {
			ByteArrayOutputStream output = new ByteArrayOutputStream();
			output.write(sessionId, 0, Message.SID_SIZE);
			output.write(lengthAckPacketId);
			
			if(lengthAckPacketId > 0) {
				output.write(ackPacketId, 0, 4 * lengthAckPacketId);
				output.write(ackRemoteSession, 0, Message.SID_SIZE);
			}
			
			output.write(packetId, 0, 4);
			return output;
		}
}
