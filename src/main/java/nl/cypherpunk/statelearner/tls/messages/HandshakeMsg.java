/*
 *  Copyright (c) 2016 Joeri de Ruiter
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

package nl.cypherpunk.statelearner.tls.messages;

import java.io.IOException;
import java.io.InputStream;

import nl.cypherpunk.statelearner.tls.Utils;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class HandshakeMsg {
	protected byte type;
	protected int length;
	protected byte[] payload;
	
	public HandshakeMsg(byte type, int length, byte[] payload) {
		this.type = type;
		this.length = length;
		this.payload = payload;
	}
	
	public HandshakeMsg(InputStream msg) throws IOException {
		type = (byte) msg.read();
		length = Utils.getuint24((byte)msg.read(), (byte)msg.read(), (byte)msg.read());
		payload = new byte[length];
		msg.read(payload, 0, length);
	}
	
	public byte getType() {
		return type;
	}
	
	public int getLength() {
		return length;
	}
	
	public byte[] getPayload() {
		return payload;
	}
	
	public byte[] getBytes() {
		byte[] out = new byte[payload.length + 4];
		
		out[0] = type;
		out[1] = (byte)(0xFF & (length >>> 16));
		out[2] = (byte)(0xFF & (length >>> 8));
		out[3] = (byte)(0xFF & length);
		
		for(int i = 0; i < payload.length; i++) {
			out[i + 4] = payload[i];
		}
		
		return out;
	}
}
