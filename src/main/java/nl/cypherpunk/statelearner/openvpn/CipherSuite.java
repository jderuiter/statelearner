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

package nl.cypherpunk.statelearner.openvpn;

import java.io.ByteArrayOutputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import nl.cypherpunk.statelearner.tls.TLS12;

public class CipherSuite {

	String cipherAlgo;
	String auhtAlgo;

	// Encryption / Decryption material
	byte   cipherLength; // Cipher key length in bytes (1 byte)
	byte   ivLength;
	byte[] readKey;      // Cipher key (n bytes)
	byte[] writeKey;     // Cipher key (n bytes)
	byte[] writeIV;
	byte[] readIV;
	Cipher readCipher;
	Cipher writeCipher;

	// Authentification material
	byte   hmacLength;   // HMAC key length in bytes (1 byte)
	byte[] readMacKey;   // HMAC key (n bytes)
	byte[] writeMacKey;
	Mac readMac;
	Mac writeMac;

	// Ramdom material from both peers (for key method2)
	byte[] preMaster;
	byte[] clientRand1;
	byte[] serverRand1;
	byte[] clientRand2;
	byte[] serverRand2;
	byte[] keyBlock;

	SecureRandom rand;

	public CipherSuite(SecureRandom rand) {
		this.rand = rand;

		// Set default ciphers/authentication algo
		setCipherAlgo("Blowfish");

		// Init material for key method 2
		this.preMaster = new byte[48];
		this.clientRand1 = new byte[32];
		this.clientRand2 = new byte[32];
		this.serverRand1 = new byte[32];
		this.serverRand2 = new byte[32];
		rand.nextBytes(preMaster);
		rand.nextBytes(clientRand1);
		rand.nextBytes(clientRand2);
		rand.nextBytes(serverRand1);
		rand.nextBytes(serverRand2);
	}

	public void setCipherAlgo(String cipherAlgo) {
		if(cipherAlgo.equals("Blowfish")) {
			this.cipherAlgo = "Blowfish";
			this.cipherLength = 16;
			this.ivLength = 8;
		} else if(cipherAlgo.equals("AES")) {
			this.cipherAlgo = "AES";
			this.cipherLength = 32;
			this.ivLength = 16;
		} else {
			throw new IllegalArgumentException("Unknown cipher algorithm");
		}

		// Write material
		writeKey = new byte[cipherLength];
		writeIV = new byte[ivLength];
		rand.nextBytes(writeKey);
		rand.nextBytes(writeIV);
		this.writeCipher = null;

		// Read material
		readKey = new byte[cipherLength];
		readIV = new byte[ivLength];
		Arrays.fill(readKey, (byte) 0);
		Arrays.fill(readIV, (byte) 0);
		this.readCipher = null;
	}

	public void setAuthAlgo(String authAlgo) {
		if(authAlgo.equals("HmacSHA1")) {
			this.auhtAlgo = "HmacSHA1";
			this.hmacLength = 20;
		} else if(authAlgo.equals("HmacSHA256")) {
			this.auhtAlgo = "HmacSHA256";
			this.hmacLength = 32;
		} else {
			throw new IllegalArgumentException("Unknown authentication algorithm");
		}

		// Write material
		writeMacKey = new byte[hmacLength];
		rand.nextBytes(writeMacKey);
		this.writeMac = null;

		// Read material
		readMacKey = new byte[hmacLength];
		Arrays.fill(readMacKey, (byte) 0);
		this.readMac = null;
	}

	public byte getCypherLength() {
		return cipherLength;
	}
	
	public byte getHmacLength() {
		return hmacLength;
	}
	
	public Cipher getWriteCipher() throws Exception {
		if(writeCipher == null)
			setWriteCipher();
		return writeCipher;
	}
	public Mac getWriteMac() throws Exception {
		if(writeMac == null)
			setWriteMac();
		return writeMac;
	}
	
	public byte[] getReadKey() {
		return readKey;
	}
	
	public void setReadKey(byte[] readKey) {
		this.readKey = readKey;
		this.readCipher = null;
	}
	
	public byte[] getWriteKey() {
		return writeKey;
	}
	
	public void setWriteKey(byte[] writeKey) {
		this.writeKey = writeKey;
		this.writeCipher = null;
	}
	
	public Cipher getReadCipher() throws Exception {
		if(readCipher == null)
			setReadCipher();
		return readCipher;
	}
	
	public void setReadMacKey(byte[] readMacKey) {
		this.readMacKey = readMacKey;
		this.readMac = null;
	}
	
	public void setWriteMacKey(byte[] writeMacKey) {
		this.writeMacKey = writeMacKey;
		this.writeMac = null;
	}
	
	public Mac getReadMac() throws Exception {
		if(readMac == null)
			setReadMac();
		return readMac;
	}
	
	public void setWriteIV(byte[] writeIV) {
		this.writeIV = writeIV;
		this.writeCipher = null;
	}
	
	public void setReadIV(byte[] readIV) {
		this.readIV = readIV;
		this.readCipher = null;
	}

	private void setWriteCipher() throws Exception {
		SecretKey cipherKey = new SecretKeySpec(this.writeKey, this.cipherAlgo);
		IvParameterSpec cipherIV = new IvParameterSpec(this.writeIV);

		// Set up decryption cipher
		switch(this.cipherAlgo) {
		case "Blowfish": this.writeCipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding"); break;
		case "AES": this.writeCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); break;
		default: throw new IllegalArgumentException("No Algorithm specified");
		}
		writeCipher.init(Cipher.ENCRYPT_MODE, cipherKey, cipherIV);
	}

	private void setWriteMac() throws Exception {
		SecretKey cipherMacKey = new SecretKeySpec(this.writeMacKey, this.auhtAlgo);

		// Set up MAC cipher
		switch(this.auhtAlgo) {
		case "HmacSHA1": this.writeMac = Mac.getInstance("HmacSHA1"); break;
		case "HmacSHA256": this.writeMac = Mac.getInstance("HmacSHA256"); break;
		default: throw new IllegalArgumentException("No Algorithm specified");
		}
		this.writeMac.init(cipherMacKey);
	}

	private void setReadCipher() throws Exception {
		SecretKey cipherKey = new SecretKeySpec(this.readKey, this.cipherAlgo);
		IvParameterSpec cipherIV = new IvParameterSpec(this.readIV);

		// Set up decryption cipher
		switch(this.cipherAlgo) {
		case "Blowfish": this.readCipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding"); break;
		case "AES": this.readCipher = Cipher.getInstance("AES/CBC/PKCS5Padding"); break;
		default: throw new IllegalArgumentException("No Algorithm specified");
		}
		readCipher.init(Cipher.DECRYPT_MODE, cipherKey, cipherIV);
	}

	private void setReadMac() throws Exception {
		SecretKey cipherMacKey = new SecretKeySpec(this.readMacKey, this.auhtAlgo);

		// Set up MAC cipher
		switch(this.auhtAlgo) {
		case "HmacSHA1": this.readMac = Mac.getInstance("HmacSHA1"); break;
		case "HmacSHA256": this.readMac = Mac.getInstance("HmacSHA256"); break;
		default: throw new IllegalArgumentException("No Algorithm specified");
		}
		this.readMac.init(cipherMacKey);
	}

	public int getIvLength() {
		return this.writeCipher.getIV().length;
	}

	public byte[] getPreMaster() {
		return preMaster;
	}

	public void setPreMaster(byte[] preMaster) {
		this.preMaster = preMaster;
	}

	public byte[] getClientRand1() {
		return clientRand1;
	}

	public void setClientRand1(byte[] clientRand1) {
		this.clientRand1 = clientRand1;
	}

	public byte[] getServerRand1() {
		return serverRand1;
	}

	public void setServerRand1(byte[] serverRand1) {
		this.serverRand1 = serverRand1;
	}

	public byte[] getClientRand2() {
		return clientRand2;
	}

	public void setClientRand2(byte[] clientRand2) {
		this.clientRand2 = clientRand2;
	}

	public byte[] getServerRand2() {
		return serverRand2;
	}

	public void setServerRand2(byte[] serverRand2) {
		this.serverRand2 = serverRand2;
	}

	public void computeKeyBlock(byte[] clientSid, byte[] serverSid) throws InvalidKeyException, NoSuchAlgorithmException, Exception {

		// Compute master secret
		byte[] master = PRF(preMaster, "OpenVPN master secret", clientRand1, serverRand1, null, null, 48);

		// Compute key expansion
		keyBlock = PRF(master, "OpenVPN key expansion", clientRand2, serverRand2, clientSid, serverSid, 256);	

		// Extract keys from key block
		this.writeKey = Arrays.copyOfRange(keyBlock, 0, 0 + cipherLength);
		this.writeMacKey = Arrays.copyOfRange(keyBlock, 64, 64 + hmacLength);
		this.readKey = Arrays.copyOfRange(keyBlock, 128, 128 + cipherLength);
		this.readMacKey = Arrays.copyOfRange(keyBlock, 192, 192 + hmacLength);

		this.readCipher = null;
		this.readMac = null;
		this.writeCipher = null;
		this.writeMac = null;
	}

	private byte[] PRF(byte[] secret, String label, byte[] clientSeed, byte[] serverSeed, byte[] clientSid, byte[] serverSid, int length) throws InvalidKeyException, NoSuchAlgorithmException, Exception {
		// Concatenate seed components
		ByteArrayOutputStream seed = new ByteArrayOutputStream();

		seed.write(label.getBytes());
		seed.write(clientSeed);
		seed.write(serverSeed);

		if(clientSid != null) {
			seed.write(clientSid);
		}
		if(serverSid != null) {
			seed.write(serverSid);
		}

		// Compute PRF
		byte output[] = TLS12.tls1_PRF(seed.toByteArray(), secret, length);

		return output;
	}

}