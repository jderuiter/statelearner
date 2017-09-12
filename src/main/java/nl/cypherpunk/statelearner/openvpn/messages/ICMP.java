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
import java.util.Arrays;
import java.util.Date;

import com.google.common.primitives.Longs;

public class ICMP {
	// IP packet
	protected byte version;
	protected byte headerLength;
	protected byte service;
	protected byte[] totalLength;
	protected byte[] identification;
	protected byte[] flags_fragOffset;
	protected byte ttl;
	protected byte proto; // ICMP = 1
	protected byte[] ipchecksum; // TODO compute this checksum
	protected byte[] source; // 10.8.0.2
	protected byte[] dest; // 10.8.0.1

	// ICMP packet
	protected byte type; // Echo request = 8/ Echo reply = 0
	protected byte code;
	protected byte[] checksum; // TODO compute this checksum
	protected byte[] id;
	protected byte[] sequence;
	protected byte[] timestamp; // TODO compute timestamp

	protected byte[] data;

	public ICMP() {
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

	protected void prepare() throws IOException {
		Date time = new Date();
		timestamp = Longs.toByteArray(time.getTime());
		Arrays.fill(checksum, (byte) 0);
		Arrays.fill(ipchecksum, (byte) 0);
		checksum = Longs.toByteArray(computeChecksum());
		ipchecksum = Longs.toByteArray(computeIPChecksum());
	}

	protected long computeChecksum() throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		stream.write(type);
		stream.write(code);
		stream.write(checksum);
		stream.write(id);
		stream.write(sequence);
		stream.write(timestamp);
		stream.write(data);
		return computeChecksum(stream.toByteArray());
	}

	protected long computeIPChecksum() throws IOException {
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		byte version_headerLength = (byte) (version << 4 | headerLength);
		stream.write(version_headerLength);
		stream.write(service);
		stream.write(totalLength);
		stream.write(identification);
		stream.write(flags_fragOffset);
		stream.write(ttl);
		stream.write(proto);
		stream.write(ipchecksum);
		stream.write(source);
		stream.write(dest);
		stream.write(type);
		stream.write(code);
		stream.write(checksum);
		stream.write(id);
		stream.write(sequence);
		stream.write(timestamp);
		stream.write(data);	
		return computeChecksum(stream.toByteArray());
	}

	protected int computeChecksum(byte [] buf) throws IOException {
		int sum = 0;
		for(int i = 0; i < buf.length; ++i) {
			sum += buf[i];
		}
		return sum;
	}

	public static boolean isPingReply(byte[] payload) {
		// Check if proto = ICMP
		if(payload[9] != 1) {
			return false;
		}
		// Check if it is an echo reply
		if(payload[20] != 0) {
			return false;
		}
		return true;
	}
}
