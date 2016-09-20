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
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import javax.crypto.spec.DHPublicKeySpec;

import nl.cypherpunk.statelearner.tls.TLS;
import nl.cypherpunk.statelearner.tls.TLSByteArrayInputStream;
import nl.cypherpunk.statelearner.tls.Utils;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class ServerKeyExchange extends HandshakeMsg {
		byte[] dh_p;
		byte[] dh_g;
		byte[] dh_Ys;
		int hash_alg;
		int signature_alg;
		byte[] signature;
		
		public ServerKeyExchange(HandshakeMsg hs) throws IOException {
			super(hs.getType(), hs.getLength(), hs.getPayload());
			
			TLSByteArrayInputStream inStream = new TLSByteArrayInputStream(payload);
			
			int len_dh_p = inStream.getInt16(); 
			dh_p = new byte[len_dh_p];
			inStream.read(dh_p, 0, len_dh_p);
			
			int len_dh_g = inStream.getInt16(); 
			dh_g = new byte[len_dh_g];
			inStream.read(dh_g, 0, len_dh_g);
			
			int len_dh_Ys = inStream.getInt16(); 
			dh_Ys = new byte[len_dh_Ys];
			inStream.read(dh_Ys, 0, len_dh_Ys);
			
			if(inStream.available() > 0) {
				hash_alg = inStream.read();
				signature_alg = inStream.read();
				int len_signature = inStream.getInt16();
				signature = new byte[len_signature];
				inStream.read(signature, 0, len_signature);
			}
			
			inStream.close();
		}
		
		public ServerKeyExchange(byte[] dh_p, byte[] dh_g, byte[] dh_Ys, int hash_alg, int signature_alg, byte[] signature) throws IOException {
			super(TLS.HANDSHAKE_MSG_TYPE_SERVER_KEY_EXCHANGE, 0, new byte[] {});	
			
			this.dh_p = dh_p;
			this.dh_g = dh_g;
			this.dh_Ys = dh_Ys;
			this.hash_alg = hash_alg;
			this.signature_alg = signature_alg;
			this.signature = signature;
			
			ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
			
			payloadStream.write(Utils.getbytes16(dh_p.length));
			payloadStream.write(dh_p);
			
			payloadStream.write(Utils.getbytes16(dh_g.length));
			payloadStream.write(dh_g);
			
			payloadStream.write(Utils.getbytes16(dh_Ys.length));
			payloadStream.write(dh_Ys);
			
			// TODO Remove for TLSv1.0
			payloadStream.write(Utils.getbytes8(hash_alg));
			payloadStream.write(Utils.getbytes8(signature_alg));
			
			payloadStream.write(Utils.getbytes16(signature.length));
			payloadStream.write(signature);
			
			payload = payloadStream.toByteArray();
			length = payload.length;
		}
		
		public BigInteger getP() {
			return new BigInteger(Utils.concat(new byte[] {0x00}, dh_p));
		}
		
		public BigInteger getG() {
			return new BigInteger(Utils.concat(new byte[] {0x00}, dh_g));
		}
		
		public PublicKey getPublicKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
			KeyFactory keyFactory = KeyFactory.getInstance("DH");
			DHPublicKeySpec pubKeySpec = new DHPublicKeySpec(new BigInteger(Utils.concat(new byte[] {0x00}, dh_Ys)), new BigInteger(Utils.concat(new byte[] {0x00}, dh_p)), new BigInteger(Utils.concat(new byte[] {0x00}, dh_g)));
		    PublicKey pubKey = keyFactory.generatePublic(pubKeySpec);

			return pubKey;
		}
}