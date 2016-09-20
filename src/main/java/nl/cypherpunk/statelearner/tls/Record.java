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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.Mac;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class Record {
	private byte contentType;
	private ProtocolVersion protocolVersion;
	private byte lengthLSB;
	private byte lengthMSB;
	private int length;
	private byte[] payload;
	private byte[] mac;
	
	public Record(InputStream input) throws IOException {
		contentType = (byte) input.read();
		
		int majorVersion = input.read();
		int minorVersion = input.read();
		protocolVersion = new ProtocolVersion(majorVersion, minorVersion);
		
		lengthMSB = (byte)input.read();
		lengthLSB = (byte)input.read();
		length = Utils.getuint16(lengthMSB, lengthLSB);
		
		payload = new byte[length];
		input.read(payload, 0, length);
		
		mac = new byte[0];
	}
	
	public Record(byte contentType, InputStream input) throws IOException {
		this.contentType = contentType;
		
		int majorVersion = input.read();
		int minorVersion = input.read();
		protocolVersion = new ProtocolVersion(majorVersion, minorVersion);
		
		lengthMSB = (byte)input.read();
		lengthLSB = (byte)input.read();
		length = Utils.getuint16(lengthMSB, lengthLSB);
		
		payload = new byte[length];
		input.read(payload, 0, length);
		
		mac = new byte[0];
	}
	
	public Record(byte contentType, ProtocolVersion protocolVersion, byte[] payload) {
		this.contentType = contentType;
		this.protocolVersion = protocolVersion;
		this.payload = payload;
		
		length = payload.length;
        lengthMSB = (byte)(0xFF & (length >>> 8));
        lengthLSB = (byte)(0xFF & length);
	}
	
	public void decrypt(Cipher cipher, int macSize) throws Exception {
		byte[] tmp = cipher.update(payload, 0, payload.length);
        if(tmp.length < macSize) throw new Exception("Error decrypting");
        
        // Extract padding length from padding
   	    int pad_len = tmp[tmp.length - 1] & 0xFF;
   	    byte padding = tmp[tmp.length - 1];
   	    
   	    // Check padding

   	    // This is ignored because in certain cases it results in problems with invalid decryptions
   	    //if(pad_len == 0) throw new Exception("Error decrypting: 0 padding value");
   	    
   	    if(pad_len < 0 || pad_len > 255) throw new Exception("Error decrypting: invalid padding value");
   	    if(pad_len >= tmp.length) throw new Exception("Error decrypting: padding too long");
   	    
   	    for(int i = tmp.length - pad_len - 1; i < tmp.length; i++)
   	    	if(tmp[i] != padding) {
   	    		throw new Exception("Error decrypting: invalid padding");
   	    	}
   	    
   	    if(protocolVersion.val < ProtocolVersion.TLS11.val) {
   	    	if(tmp.length < (macSize + pad_len)) throw new Exception("Error decrypting: data too short");
   	    	
   	    	payload = Arrays.copyOfRange(tmp, 0, tmp.length - macSize - pad_len - 1);
   	    }
   	    else {
   	    	if(tmp.length < (cipher.getBlockSize() + macSize + pad_len)) throw new Exception("Error decrypting: data too short");
   	    	
    	    // Discard IV and padding
    	    payload = Arrays.copyOfRange(tmp, cipher.getBlockSize(), tmp.length - macSize - pad_len - 1);
   	    }
   	    mac = Arrays.copyOfRange(tmp, tmp.length - macSize - pad_len - 1, tmp.length - pad_len - 1);
        
   	    // Update length
        length = payload.length;
        lengthMSB = (byte)(0xFF & (length >>> 8));
        lengthLSB = (byte)(0xFF & length);
	}
	
	public void encrypt(Cipher cipher, SecureRandom rand) throws Exception {
		byte[] iv = new byte[] {};
		int new_len;
		
		if(protocolVersion.val < ProtocolVersion.TLS11.val) {
			new_len = (int) (Math.ceil((payload.length) / cipher.getBlockSize()) + 1) * cipher.getBlockSize();
		}
		else {
			new_len = (int) (Math.ceil((payload.length)/ cipher.getBlockSize()) + 2) * cipher.getBlockSize();
		
   		  	// Generate random IV
			iv = new byte[cipher.getBlockSize()];
			rand.nextBytes(iv);
		}
		
		byte[] tmp = new byte[new_len];

		// Copy IV
		System.arraycopy(iv, 0, tmp, 0, iv.length);

		// Add payload
		System.arraycopy(payload, 0, tmp, iv.length, payload.length);
			
		// Add padding
		int pad_len = new_len - iv.length - payload.length;
		for(int i = iv.length + payload.length; i < tmp.length; i++)
			tmp[i] = (byte)(pad_len-1);

		// Encrypt payload
		payload = cipher.update(tmp);
		
		// Update length
		length = payload.length;
        lengthMSB = (byte)(0xFF & (length >>> 8));
        lengthLSB = (byte)(0xFF & length);
	}
	
	public boolean checkMAC(Mac readMAC, long sequence_number) {
		readMAC.reset();
		readMAC.update((byte)(0xFF & (sequence_number >>> 56)));
		readMAC.update((byte)(0xFF & (sequence_number >>> 48)));
		readMAC.update((byte)(0xFF & (sequence_number >>> 40)));
		readMAC.update((byte)(0xFF & (sequence_number >>> 32)));
		readMAC.update((byte)(0xFF & (sequence_number >>> 24)));
		readMAC.update((byte)(0xFF & (sequence_number >>> 16)));
		readMAC.update((byte)(0xFF & (sequence_number >>> 8)));
		readMAC.update((byte)(0xFF & sequence_number));
		readMAC.update(contentType);
		readMAC.update(protocolVersion.getMajorVersion());
		readMAC.update(protocolVersion.getMinorVersion());
		readMAC.update(lengthMSB);
		readMAC.update(lengthLSB);
		readMAC.update(payload);
		byte[] mac = readMAC.doFinal();
		
		for(int i = 0; i < mac.length; i++) {
			if(mac[i] != this.mac[i]) return false;
		}
		
		return true;
	}
	
	public void addMAC(Mac writeMAC, int hashSize, long sequence_number) throws Exception {
		byte[] tmp = payload;
		payload = new byte[tmp.length + hashSize];
		System.arraycopy(tmp, 0, payload, 0, tmp.length);
		
		ByteArrayOutputStream macInput = new ByteArrayOutputStream();
		macInput.write(Utils.getbytes64(sequence_number));
		macInput.write(new byte[] {contentType, protocolVersion.getMajorVersion(), protocolVersion.getMinorVersion(), lengthMSB, lengthLSB});
		macInput.write(tmp);
		
		writeMAC.reset();
		writeMAC.update(macInput.toByteArray());		
		writeMAC.doFinal(payload, payload.length - hashSize);
		
		length = payload.length;
        lengthMSB = (byte)(0xFF & (length >>> 8));
        lengthLSB = (byte)(0xFF & length);
	}
	
	public byte getContentType() {
		return contentType;
	}
	
	public ProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}
	
	public byte[] getPayload() {
		return payload;
	}
	
	public byte[] getMAC() {
		return mac;
	}
	
	public int getLength() {
		return length;
	}
	
	public byte[] getBytes() {
		byte[] output = new byte[5 + payload.length];
		output[0] = contentType;
		output[1] = protocolVersion.getMajorVersion();
		output[2] = protocolVersion.getMinorVersion();
		output[3] = (byte)(0xFF & lengthMSB);
		output[4] = (byte)(0xFF & lengthLSB);
		
		for(int i = 0; i < payload.length; i++) {
			output[5 + i] = payload[i];
		}
		
		return output;
	}
}

