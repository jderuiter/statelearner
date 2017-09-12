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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

public class ICMPRequest extends ICMP{
	public ICMPRequest() {
		// IP packet
		version = 0x04;
		headerLength = 0x05;
		service = 0x00;
		byte[] totalLength = { 0x00, 0x54 };
		this.totalLength = totalLength;
		byte[] identification = { (byte) 0xd2, 0x26 };
		this.identification = identification;
		byte[] flags_fragOffset = { 0x40, 0x00 };
		this.flags_fragOffset = flags_fragOffset;
		ttl = (byte) 0x40;
		proto = 0x01; // ICMP
		byte[] ipchecksum = { 0x54, 0x70}; // TODO compute this checksum
		this.ipchecksum = ipchecksum;
		byte[] source = { 0x0a, 0x08, 0x00, 0x02 }; // 10.8.0.2
		this.source = source;
		byte[] dest = {0x0a, 0x08, 0x00, 0x01 }; // 10.8.0.1
		this.dest = dest;
		
		// ICMP packet
		type = 0x8; // Echo request
		code = 0x0;
		byte[] checksum = { 0x7f, 0x03 }; // TODO compute this checksum
		this.checksum = checksum;
		byte[] id = { 0x05, 0x47 };
		this.id = id;
		byte[] sequence = { 0x00, 0x01 };
		this.sequence = sequence;
		byte[] timestamp = { 0x06, (byte) 0xfa, 0x22, 0x59, 0x00, 0x00, 0x00, 0x00 }; // TODO compute timestamp
		this.timestamp = timestamp;
		
		byte[] data = {(byte) 0x81, (byte) 0x8e, 0x0a, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
				0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
				0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
				0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
				0x33, 0x34, 0x35, 0x36, 0x37 };
		this.data = data;
	}
	
	public byte[] getBytes() throws IOException {
		ByteArrayOutputStream packet = new ByteArrayOutputStream();
		//prepare();
		byte version_headerLength = (byte) (version << 4 | headerLength);
		packet.write(version_headerLength);
		packet.write(service);
		packet.write(totalLength);
		packet.write(identification);
		packet.write(flags_fragOffset);
		packet.write(ttl);
		packet.write(proto);
		packet.write(ipchecksum);
		packet.write(source);
		packet.write(dest);
		packet.write(type);
		packet.write(code);
		packet.write(checksum);
		packet.write(id);
		packet.write(sequence);
		packet.write(timestamp);
		packet.write(data);
		return packet.toByteArray();
	}
}
