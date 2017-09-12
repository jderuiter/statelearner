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
public class TLS12 extends TLS {
	public static final byte TLS_PRF_SHA256 = 0x01;
	
	public static byte PRFAlgorithm = TLS_PRF_SHA256; 
	
	public TLS12() {
		protocolVersion = ProtocolVersion.TLS12;
	}
	
	public static byte[] P_SHA256(byte[] secret, byte[] seed) throws Exception {
		byte[] output = {};
		byte[] A = seed;
		
		for(int i = 0; i < 4; i++) {
			A = Crypto.HMAC_SHA256(secret, A);
			output = Utils.concat(output, Crypto.HMAC_SHA256(secret, Utils.concat(A, seed)));
		}
		
		return output;
	}
	
	public static byte[] P_SHA1(byte[] secret, byte[] seed, int length) throws Exception {
		byte[] output = {};
		byte[] A = seed;
		
		int n = length % 20 == 0 ? length / 20 : length / 20 + 1;
		// 160 bits = 20 bytes
		for(int i = 0; i < n; i++) {
			A = Crypto.HMAC_SHA1(secret, A);
			output = Utils.concat(output, Crypto.HMAC_SHA1(secret, Utils.concat(A, seed)));
		}
		
		return Arrays.copyOf(output, length);
	}
	
	public static byte[] P_MD5(byte[] secret, byte[] seed, int length) throws Exception {
		byte[] output = {};
		byte[] A = seed;
		
		int n = length % 16 == 0 ? length / 16 : length / 16 + 1;
		// 128 bits = 16 bytes
		for(int i = 0; i < n; i++) {
			A = Crypto.HMAC_MD5(secret, A);
			output = Utils.concat(output, Crypto.HMAC_MD5(secret, Utils.concat(A, seed)));
		}
		
		return Arrays.copyOf(output, length);
	}
	
	public static byte[] tls1_PRF(byte[] label, byte[] sec, int olen) throws Exception {
		int len = sec.length / 2;
		byte[] S1 = Arrays.copyOfRange(sec, 0, len + (sec.length & 1));
		byte[] S2 = Arrays.copyOfRange(sec, len, sec.length);
		 
		byte[] out1 = P_MD5(S1, label, olen);
		byte[] out2 = P_SHA1(S2, label, olen);
		
		for(int i = 0; i < olen; i++) {
			out1[i] ^= out2[i];
		}
		
		return out1;
	}
	
	public static byte[] PRF(byte[] secret, String label, byte[] seed) throws InvalidKeyException, NoSuchAlgorithmException, Exception {
		if(PRFAlgorithm == TLS_PRF_SHA256)
			return P_SHA256(secret, Utils.concat(label.getBytes(), seed));
		else
			throw new Exception("Unknown PRFAlgorithm: " + PRFAlgorithm);
	}
	
	public byte[] masterSecret(byte[] preMasterSecret, byte[] serverRandom, byte[] clientRandom) throws Exception {
		return Arrays.copyOf(PRF(preMasterSecret, "master secret", Utils.concat(clientRandom, serverRandom)), 48);
	}
	
	public byte[] keyblock(byte[] masterSecret, byte[] serverRandom, byte[] clientRandom) throws Exception {
		return PRF(masterSecret, "key expansion", Utils.concat(serverRandom, clientRandom));
	}
	
	public byte[] verifyDataClient(byte[] masterSecret, byte[] handshakeMessages) throws Exception {
		if(PRFAlgorithm == TLS_PRF_SHA256)
			return Arrays.copyOf(PRF(masterSecret, "client finished", Crypto.SHA256(handshakeMessages)), 12);
		else
			throw new Exception("Unknown PRFAlgorithm: " + PRFAlgorithm);
	}
	
	public byte[] verifyDataServer(byte[] masterSecret, byte[] handshakeMessages) throws Exception {
		if(PRFAlgorithm == TLS_PRF_SHA256)
			return Arrays.copyOf(PRF(masterSecret, "server finished", Crypto.SHA256(handshakeMessages)), 12);
		else
			throw new Exception("Unknown PRFAlgorithm: " + PRFAlgorithm);
	}
}
