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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import nl.cypherpunk.statelearner.tls.CipherSuite;
import nl.cypherpunk.statelearner.tls.ProtocolVersion;
import nl.cypherpunk.statelearner.tls.TLS;
import nl.cypherpunk.statelearner.tls.Utils;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class ServerHello extends HandshakeMsg {
	ProtocolVersion protocolVersion;
	byte[] random = new byte[32];
	byte[] sessionId;
	byte[] cipherSuite = new byte[2];
	byte compressionMethod;
	byte[] extensions;
	
	public ServerHello(HandshakeMsg hs) {
		super(hs.getType(), hs.getLength(), hs.getPayload());
		
		// Parse payload
		byte[] payload = hs.getPayload();
		// ProtocolVersion
		protocolVersion = new ProtocolVersion(payload[0], payload[1]);
		// Random
		System.arraycopy(payload, 2, random, 0, 32);
		// SessionID
		int lenSessionID = payload[34];
		sessionId = new byte[lenSessionID];
		System.arraycopy(payload, 35, sessionId, 0, lenSessionID);
		// CipherSuite
		cipherSuite[0] = payload[35 + lenSessionID];
		cipherSuite[1] = payload[36 + lenSessionID];
		// CompressionMethod
		compressionMethod = payload[37 + lenSessionID];
		// Extensions
		int lenExtensions = payload.length - lenSessionID - 38;
		extensions = new byte[lenExtensions];
		System.arraycopy(payload, lenSessionID + 38, extensions, 0, lenExtensions);
	}
	
	public ServerHello(ProtocolVersion protocolVersion, byte[] random, byte[] sessionId, byte[] cipherSuite, byte compressionMethod, byte[] extensions) throws IOException {
		super(TLS.HANDSHAKE_MSG_TYPE_SERVER_HELLO, 0, new byte[] {});
		
		this.protocolVersion = protocolVersion;
		this.random = random;
		this.sessionId = sessionId;
		this.cipherSuite = cipherSuite;
		this.compressionMethod = compressionMethod;
		this.extensions = extensions;
		
		ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
		payloadStream.write(protocolVersion.getBytes());
		payloadStream.write(random);
		payloadStream.write(Utils.getbytes8(sessionId.length));
		payloadStream.write(sessionId);
		payloadStream.write(cipherSuite);
		payloadStream.write(new byte[] { compressionMethod} );
		if(extensions.length > 0) {
			payloadStream.write(Utils.getbytes16(extensions.length));
			payloadStream.write(extensions);
		}
		
		payload = payloadStream.toByteArray();
		length = payload.length;
	}
	
	public CipherSuite getCipherSuite() throws Exception {
		return new CipherSuite(cipherSuite);
	}
	
	public ProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}
	
	public byte[] getRandom() {
		return random;
	}
	
	public byte[] getSessionId() {
		return sessionId;
	}

}
