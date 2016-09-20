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

import java.util.Arrays;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class Utils {
	public static byte[] concat(byte[] first, byte[] second) {
		if (first == null) return second;
		if(second == null) return first;
		
		byte[] result = Arrays.copyOf(first, first.length + second.length);
		System.arraycopy(second, 0, result, first.length, second.length);
		return result;
	}
	
	public static byte[] xor(byte[] first, byte[] second) throws Exception {
		if(first.length != second.length) throw new Exception("Arguments have different lengths");
		
		byte[] output = new byte[first.length];
		
		for(int i = 0; i < first.length; i++) {
			output[i] = (byte)(first[i] ^ second[i]);
		}
		
		return output;
	}

	public static int getuint16(byte byte1, byte byte2) {
		return ((byte1 & 0xFF) << 8) | (byte2 & 0xFF);
	}
	
	public static int getuint24(byte byte1, byte byte2, byte byte3) {
		return ((byte1 & 0xFF) << 16) | ((byte2 & 0xFF) << 8) | (byte3 & 0xFF);
	}
	
	public static byte[] getbytes64(long val) {
		byte[] out = new byte[8];
		out[0] = (byte)(0xFF & (val >>> 56));
		out[1] = (byte)(0xFF & (val >>> 48));
		out[2] = (byte)(0xFF & (val >>> 40));
		out[3] = (byte)(0xFF & (val >>> 32));
		out[4] = (byte)(0xFF & (val >>> 24));
		out[5] = (byte)(0xFF & (val >>> 16));
		out[6] = (byte)(0xFF & (val >>> 8));
		out[7] = (byte)(0xFF & val);
		return out;		
	}
	
	public static byte[] getbytes24(int val) {
		byte[] out = new byte[3];
		out[0] = (byte)(0xFF & (val >>> 16));
		out[1] = (byte)(0xFF & (val >>> 8));
		out[2] = (byte)(0xFF & val);
		return out;		
	}
	
	public static byte[] getbytes16(int val) {
		byte[] out = new byte[2];
		out[0] = (byte)(0xFF & (val >>> 8));
		out[1] = (byte)(0xFF & val);
		return out;		
	}
	
	public static byte[] getbytes8(int val) {
		byte[] out = new byte[1];
		out[0] = (byte)(0xFF & val);
		return out;		
	}	
	
	private static String CHARS = "0123456789ABCDEF";
	public static String bytesToHex(byte[] bytes) {
		StringBuffer hex = new StringBuffer();
		
		for(int i = 0; i < bytes.length; i++) {
			int n1 = (bytes[i] >> 4) & 0x0F;
			hex.append(CHARS.charAt(n1));
			int n2 = bytes[i] & 0x0F;
			hex.append(CHARS.charAt(n2));
		}
		
		return hex.toString();
	}
}
