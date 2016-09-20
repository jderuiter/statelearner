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
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import nl.cypherpunk.statelearner.tls.TLS;
import nl.cypherpunk.statelearner.tls.TLSByteArrayInputStream;
import nl.cypherpunk.statelearner.tls.Utils;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class Certificate extends HandshakeMsg {
	PublicKey pubKey;
	
	public Certificate(HandshakeMsg msg) throws IOException, CertificateException {
		super(msg.getType(),msg.getLength(), msg.getPayload());

		TLSByteArrayInputStream inStream = new TLSByteArrayInputStream(payload);
		
		// Read chain length
		int chain_len = inStream.getInt24();
		if(chain_len <= 0) {
			pubKey = null;
			inStream.close();
			return;
		}
		
		// Read certificate length
		int cert_len = inStream.getInt24();
		if(cert_len <= 0) {
			pubKey = null;
			inStream.close();
			return;
		}
		
		// Only read first certificate		
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		X509Certificate cert = (X509Certificate)cf.generateCertificate(inStream);

		// Extract public key
		pubKey = cert.getPublicKey();
	}
	
	public Certificate(X509Certificate[] certs) throws CertificateEncodingException, IOException {
		super(TLS.HANDSHAKE_MSG_TYPE_CERTIFICATE, 0, new byte[] {});
		
		ByteArrayOutputStream chainStream = new ByteArrayOutputStream();
		
		for(int i = 0; i < certs.length; i++) {
			// Add 3 byte size
			chainStream.write(Utils.getbytes24(certs[i].getEncoded().length));
			// Add certificate
			chainStream.write(certs[i].getEncoded());
		}
		
		byte[] chain = chainStream.toByteArray();
		
		ByteArrayOutputStream outStream = new ByteArrayOutputStream();
		outStream.write(Utils.getbytes24(chain.length));
		outStream.write(chain);
		
		payload = outStream.toByteArray();
		length = payload.length;
	}
	
	public PublicKey getPublicKey() {
		return pubKey;
	}

}
