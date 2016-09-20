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

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class ProtocolVersion {
	public static ProtocolVersion EMPTY = new ProtocolVersion(0x00, 0x00, "EmptyTLS");
	public static ProtocolVersion TLS10 = new ProtocolVersion(0x03, 0x01, "TLSv10");
	public static ProtocolVersion TLS11 = new ProtocolVersion(0x03, 0x02, "TLSv11");
	public static ProtocolVersion TLS12 = new ProtocolVersion(0x03, 0x03, "TLSv12");
	
	private byte minorVersion;
	private byte majorVersion;
	private String name;
	
	public int val;
	
	public ProtocolVersion(int majorVersion, int minorVersion) {
		this.majorVersion = (byte)majorVersion;
		this.minorVersion = (byte)minorVersion;
        val = Utils.getuint16(this.majorVersion, this.minorVersion);
        
        if(val == TLS10.getVal()) { name = TLS10.toString(); }
        else if(val == TLS11.getVal()) { name = TLS11.toString(); }
        else if(val == TLS12.getVal()) { name = TLS12.toString(); }
        else { name = "SSLv" + majorVersion + "." + minorVersion; }
	}
	
	public ProtocolVersion(int majorVersion, int minorVersion, String name) {
		this.majorVersion = (byte)majorVersion;
		this.minorVersion = (byte)minorVersion;
        val = Utils.getuint16(this.majorVersion, this.minorVersion);
        this.name = name;  
	}
	
	public byte getMajorVersion() {
		return majorVersion;
	}
	
	public byte getMinorVersion() {
		return minorVersion;
	}
	
	public int getVal() {
		return Utils.getuint16(this.majorVersion, this.minorVersion);
	}
	
	public byte[] getBytes() {
		return new byte[] {majorVersion, minorVersion};
	}
	
	public String toString() {
		return name;
	}
}
