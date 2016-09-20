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

package nl.cypherpunk.statelearner;

public class Utils {
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
	
	public static byte[] hexToBytes(String hex) {
		//TODO Check if string contains only hex characters
		if(hex.length() % 2 != 0) hex = "0" + hex;
		
		byte[] bytes = new byte[hex.length() / 2];
		
		for(int i = 0; i < hex.length(); i = i + 2) {
			bytes[i/2] = Integer.decode("0x" + hex.substring(i, i + 2)).byteValue();
		}
			
		return bytes;
	}
}
