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

public class ControlV1 extends Control {
	
	private byte[] payload; // The TLS payload
	
	public ControlV1(byte[] sessionId, byte[] packetId, byte[] payload) {
		super(sessionId, packetId);
		this.payload = Arrays.copyOf(payload, payload.length);
	}
	
	public ControlV1(ByteArrayInputStream input) {
		super(input);
		payload = new byte[input.available()];
		input.read(payload, 0, payload.length);
	}
	
	public byte[] getPayload() {
		return payload;
	}
	
	@Override
	public byte[] getBytes() {
		ByteArrayOutputStream output = super.getOutputStream();
		output.write(payload, 0, payload.length);
		
		return output.toByteArray();
	}
}
