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

package nl.cypherpunk.statelearner.tls;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class TLS10 extends TLS {
	public TLS10() {
		protocolVersion = ProtocolVersion.TLS10;
	}

	
	public static byte[] P_MD5(byte[] secret, byte[] seed) throws Exception {
		byte[] output = {};
		byte[] A = seed;
		
		for(int i = 0; i < 10; i++) {
			A = Crypto.HMAC_MD5(secret, A);
			output = Utils.concat(output, Crypto.HMAC_MD5(secret, Utils.concat(A, seed)));
		}
		
		return output;
	}
	
	public static byte[] P_SHA1(byte[] secret, byte[] seed) throws Exception {
		byte[] output = {};
		byte[] A = seed;
		
		for(int i = 0; i < 8; i++) {
			A = Crypto.HMAC_SHA1(secret, A);
			output = Utils.concat(output, Crypto.HMAC_SHA1(secret, Utils.concat(A, seed)));
		}
		
		return output;
	}	
	
	public static byte[] PRF(byte[] secret, String label, byte[] seed) throws InvalidKeyException, NoSuchAlgorithmException, Exception {
		int L_S1 = (int) Math.ceil((double)secret.length / 2);

		byte[] S1 = Arrays.copyOfRange(secret, 0, L_S1);
		byte[] S2 = Arrays.copyOfRange(secret, secret.length - L_S1, secret.length);
		
		return Utils.xor(P_MD5(S1, Utils.concat(label.getBytes(), seed)), P_SHA1(S2, Utils.concat(label.getBytes(), seed)));
	}
	
	public byte[] masterSecret(byte[] preMasterSecret, byte[] serverRandom, byte[] clientRandom) throws Exception {
		return Arrays.copyOf(PRF(preMasterSecret, "master secret", Utils.concat(clientRandom, serverRandom)), 48);
	}

	public byte[] keyblock(byte[] masterSecret, byte[] serverRandom, byte[] clientRandom) throws Exception {
		return PRF(masterSecret, "key expansion", Utils.concat(serverRandom, clientRandom));
	}
	
	public byte[] verifyDataClient(byte[] masterSecret, byte[] handshakeMessages) throws Exception {
		byte[] seed = new byte[36];
        byte[] md5 = Crypto.MD5(handshakeMessages);
        for(int i = 0; i < 16; i++) {
        	seed[i] = md5[i];
        }
        byte[] sha1 = Crypto.SHA1(handshakeMessages);
        for(int i = 0; i < 20; i++) {
        	seed[16 + i] = sha1[i];
        }
        	
		return Arrays.copyOf(PRF(masterSecret, "client finished", seed), 12);

	}
	
	public byte[] verifyDataServer(byte[] masterSecret, byte[] handshakeMessages) throws Exception {
		byte[] seed = new byte[36];
        byte[] md5 = Crypto.MD5(handshakeMessages);
        for(int i = 0; i < 16; i++) {
        	seed[i] = md5[i];
        }
        byte[] sha1 = Crypto.SHA1(handshakeMessages);
        for(int i = 0; i < 20; i++) {
        	seed[16 + i] = sha1[i];
        }
        	
		return Arrays.copyOf(PRF(masterSecret, "server finished", seed), 12);

	}	
}
