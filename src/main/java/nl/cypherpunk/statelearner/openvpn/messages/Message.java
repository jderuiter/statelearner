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

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;

public class Message {
	/* packet opcodes -- the V1 is intended to allow protocol changes in the future */
	public final static byte P_CONTROL_HARD_RESET_CLIENT_V1 = 1; /* initial key from client, forget previous state */
	public final static byte P_CONTROL_HARD_RESET_SERVER_V1 = 2; /* initial key from server, forget previous state */
	public final static byte P_CONTROL_SOFT_RESET_V1        = 3; /* new key, graceful transition from old to new key */
	public final static byte P_CONTROL_V1                   = 4; /* control channel packet (usually TLS ciphertext) */
	public final static byte P_ACK_V1                       = 5; /* acknowledgement for packets received */
	public final static byte P_DATA_V1                      = 6; /* data channel packet */
	public final static byte P_DATA_V2                      = 9; /* data channel packet with peer-id */

	/* indicates key_method >= 2 */
	public final static byte P_CONTROL_HARD_RESET_CLIENT_V2 = 7; /* initial key from client, forget previous state */
	public final static byte P_CONTROL_HARD_RESET_SERVER_V2 = 8; /* initial key from server, forget previous state */
	
	public final static byte SID_SIZE = 8;
	
	private byte opcode;
	private byte[] payload;

	public Message(InputStream input) throws IOException {
		// Retrieve the opcode
		opcode = (byte) input.read();
		// Retrieve the payload
		payload = new byte[input.available()];
		input.read(payload);
	}

	public Message(byte[] input) throws IOException {
		// Retrieve the opcode
		opcode = input[0];
		// Retrieve the payload
		payload = Arrays.copyOfRange(input, 1, input.length);
	}
	
	public Message(byte opcode, byte[] payload) {
		this.opcode = opcode;
		this.payload = Arrays.copyOf(payload, payload.length);
	}

	public byte getOpcode() {
		return opcode;
	}

	public byte[] getPayload() {
		return payload;
	}
	
	/**
	 * @return the total length of the message (header + payload)
	 */
	private int getLength() {
		return payload.length + 1;
	}

	/**
	 * Return the type of the message
	 */
	public byte getType() {
		return (byte) (opcode >> 0x03);
	}

	/**
	 * Return the keyId of the message
	 */
	public byte getKeyId() {
		return (byte) (opcode & (~0x07));
	}

	/**
	 * Return the byte array representation of the message.
	 */
	public byte[] getBytes() {
		byte[] output = new byte[getLength()];
		output[0] = opcode;

		for(int i = 0; i < payload.length; i++) {
			output[1 + i] = payload[i];
		}
		return output;
	}

	public boolean isControl() {
		if(	this.getType() == P_CONTROL_HARD_RESET_CLIENT_V1 ||
				this.getType() == P_CONTROL_HARD_RESET_CLIENT_V2 ||
				this.getType() == P_CONTROL_HARD_RESET_SERVER_V1 ||
				this.getType() == P_CONTROL_HARD_RESET_SERVER_V2 ||
				this.getType() == P_CONTROL_SOFT_RESET_V1 ||
				this.getType() == P_CONTROL_V1) {
			return true;
		} else {
			return false;
		}
	}

	public boolean isAck() {
		if(this.getType() == P_ACK_V1) {
			return true;
		} else {
			return false;
		}
	}

	public boolean isData() {
		if(this.getType() == P_DATA_V1 || this.getType() == P_DATA_V2) {
			return true;
		} else {
			return false;
		}
	}
}
