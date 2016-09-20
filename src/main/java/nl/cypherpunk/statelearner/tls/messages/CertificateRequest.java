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

import nl.cypherpunk.statelearner.tls.TLS;
import nl.cypherpunk.statelearner.tls.TLSByteArrayInputStream;
import nl.cypherpunk.statelearner.tls.Utils;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class CertificateRequest extends HandshakeMsg {
	byte[] cert_types;
	byte[] supported_algorithms;
	byte[] distinguished_names;
	
	public CertificateRequest(HandshakeMsg msg) throws IOException {
		super(msg.getType(),msg.getLength(), msg.getPayload());

		TLSByteArrayInputStream inStream = new TLSByteArrayInputStream(payload);
		cert_types = inStream.getBytes8();
		supported_algorithms = inStream.getBytes16();
		
		if(inStream.available() > 0) distinguished_names = inStream.getBytes16();
		
		inStream.close();
	}
	
	public CertificateRequest(byte[] cert_types, byte[] supported_algorithms, byte[] distinguished_names) throws IOException {
		super(TLS.HANDSHAKE_MSG_TYPE_CERTIFICATE_REQUEST, 0, new byte[] {});
		
		this.cert_types = cert_types;
		this.supported_algorithms = supported_algorithms;
		this.distinguished_names = distinguished_names;
		
		ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
		payloadStream.write(Utils.getbytes8(cert_types.length));
		payloadStream.write(cert_types);
		payloadStream.write(Utils.getbytes16(supported_algorithms.length));
		payloadStream.write(supported_algorithms);
		payloadStream.write(Utils.getbytes16(distinguished_names.length));
		payloadStream.write(distinguished_names);
		
		payload = payloadStream.toByteArray();
		length = payload.length;
	}
	
	public byte[] getSupportedAlgorithms() {
		return supported_algorithms;
	}
}
