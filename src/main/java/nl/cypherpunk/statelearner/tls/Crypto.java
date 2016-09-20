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
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Arrays;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class Crypto {
	public static final byte HASH_ALGORITHM_NONE = 0x00;
	public static final byte HASH_ALGORITHM_MD5 = 0x01;
	public static final byte HASH_ALGORITHM_SHA1 = 0x02;
	public static final byte HASH_ALGORITHM_SHA224 = 0x03;
	public static final byte HASH_ALGORITHM_SHA256 = 0x04;
	public static final byte HASH_ALGORITHM_SHA384 = 0x05;
	public static final byte HASH_ALGORITHM_SHA512 = 0x06;
	
	public static final byte SIGNATURE_ALGORITHM_ANONYMOUS = 0x00;
	public static final byte SIGNATURE_ALGORITHM_RSA = 0x01;
	public static final byte SIGNATURE_ALGORITHM_DSA = 0x02;
	public static final byte SIGNATURE_ALGORITHM_ECDSA = 0x03;
	
	public static final byte[] HASH_SIGNATURE_ALGORITHM_SHA1RSA = {HASH_ALGORITHM_SHA1, SIGNATURE_ALGORITHM_RSA};
	public static final byte[] HASH_SIGNATURE_ALGORITHM_SHA256RSA = {HASH_ALGORITHM_SHA256, SIGNATURE_ALGORITHM_RSA};
	
	public static byte[] MD5(byte[] message) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("MD5");
		return md.digest(message);
	}
	
	public static byte[] SHA1(byte[] message) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA1");
		return md.digest(message);
	}
	
	public static byte[] SHA256(byte[] message) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		return md.digest(message);
	}
	
	public static byte[] HMAC(String algorithm, byte[] key, byte[] message) throws Exception {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		int BLOCKSIZE = 64;
		
		if(key.length > BLOCKSIZE) {
			key = md.digest(key);
		}
		if(key.length < BLOCKSIZE) {
			key = Arrays.copyOf(key, BLOCKSIZE);
		}
		
		byte[] ipad = new byte[BLOCKSIZE];
		Arrays.fill(ipad, (byte)0x36);
		byte[] i_key_pad = Utils.xor(ipad, key);
		
		byte[] hash_i = md.digest(Utils.concat(i_key_pad, message));
		
		byte[] opad = new byte[BLOCKSIZE];
		Arrays.fill(opad, (byte)0x5C);
		byte[] o_key_pad = Utils.xor(opad, key);
		
		return md.digest(Utils.concat(o_key_pad, hash_i));
	}	
	
	public static byte[] HMAC_MD5(byte[] key, byte[] message) throws Exception {
		return HMAC("MD5", key, message);
	}
	
	public static byte[] HMAC_SHA1(byte[] key, byte[] message) throws Exception {
		return HMAC("SHA1", key, message);
	}
	
	public static byte[] HMAC_SHA256(byte[] key, byte[] message) throws Exception {
		return HMAC("SHA-256", key, message);
	}
	
	public static byte[] HMAC_SHA384(byte[] key, byte[] message) throws Exception {
		return HMAC("SHA-384", key, message);
	}
	
	public static byte[] HMAC_SHA512(byte[] key, byte[] message) throws Exception {
		return HMAC("SHA-512", key, message);
	}
	
	public static byte[] SIGN_RSA_SHA1(PrivateKey key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature instance = Signature.getInstance("SHA1withRSA");
		instance.initSign(key);
		instance.update(data);
		return instance.sign();
	}
	
	public static byte[] SIGN_RSA_SHA256(PrivateKey key, byte[] data) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException {
		Signature instance = Signature.getInstance("SHA256withRSA");
		instance.initSign(key);
		instance.update(data);
		return instance.sign();
	}
}
