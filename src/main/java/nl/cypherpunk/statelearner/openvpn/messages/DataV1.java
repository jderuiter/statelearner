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
import java.io.IOException;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;

import nl.cypherpunk.statelearner.openvpn.CipherSuite;

public class DataV1 {
	byte[] hmac;
	byte[] iv;
	byte[] packetId;
	byte[] plaintext;
	
	public DataV1(byte[] pid, byte[] plaintext) {
		this.packetId = Arrays.copyOf(pid, pid.length);
		this.plaintext = Arrays.copyOf(plaintext, plaintext.length);
	}
	
	public DataV1(ByteArrayInputStream input, CipherSuite ciphersuite) throws IllegalStateException, Exception {
		this.hmac = new byte[ciphersuite.getHmacLength()];
		this.iv = new byte[ciphersuite.getIvLength()];
		// Check the hmac
		input.read(hmac);
		byte[] authenticated = new byte[input.available()];
		input.mark(0);
		input.read(authenticated);
		byte[] expectedHmac = ciphersuite.getReadMac().doFinal(authenticated);
		if(!Arrays.equals(expectedHmac, hmac)) {
			throw new WrongHmacException("Expected: " + expectedHmac + ", received: " + hmac);
		}
		input.reset();
		input.read(iv);
		ciphersuite.setReadIV(iv);
		byte[] ciphertext = new byte[input.available()];
		input.read(ciphertext);
		byte[] plaintext = ciphersuite.getReadCipher().doFinal(ciphertext);
		this.packetId = Arrays.copyOfRange(plaintext, 0, 4);
		this.plaintext = Arrays.copyOfRange(plaintext, 4, plaintext.length);
	}

	public byte[] encrypt(Cipher writeCipher, Mac writeMac) throws IllegalBlockSizeException, BadPaddingException, ShortBufferException, IOException {
		ByteArrayOutputStream output = new ByteArrayOutputStream();
		
		// Encrypth the user plaintext and the packet ID
		ByteArrayOutputStream data = new ByteArrayOutputStream();
		data.write(packetId);
		data.write(plaintext);
		byte[] cyphertext = writeCipher.doFinal(data.toByteArray());
		
		// Authenticates the iv and data
		ByteArrayOutputStream authenticated = new ByteArrayOutputStream();	
		iv = writeCipher.getIV();
		authenticated.write(iv);
		authenticated.write(cyphertext);
		hmac = writeMac.doFinal(authenticated.toByteArray());
		
		output.write(hmac);
		output.write(authenticated.toByteArray());
		
		return output.toByteArray();
	}

	public byte[] getPayload() {
		return this.plaintext;
	}
	
	public class WrongHmacException extends Exception {
		private static final long serialVersionUID = 1L;

		public WrongHmacException(String message) {
			super(message);
		}
	}
	
	public class FailedToDecrypt extends Exception {
		private static final long serialVersionUID = 1L;

		public FailedToDecrypt(String message) {
			super(message);
		}
	}
}
