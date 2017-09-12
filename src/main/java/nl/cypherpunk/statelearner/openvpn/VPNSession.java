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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

import nl.cypherpunk.statelearner.openvpn.TLSSessionHandler.AckSession;
import nl.cypherpunk.statelearner.openvpn.messages.Ack;
import nl.cypherpunk.statelearner.openvpn.messages.ControlV1;
import nl.cypherpunk.statelearner.openvpn.messages.DataV1;
import nl.cypherpunk.statelearner.openvpn.messages.HardReset;
import nl.cypherpunk.statelearner.openvpn.messages.ICMP;
import nl.cypherpunk.statelearner.openvpn.messages.ICMPRequest;
import nl.cypherpunk.statelearner.openvpn.messages.Message;
import nl.cypherpunk.statelearner.openvpn.messages.SoftResetV1;
import nl.cypherpunk.statelearner.tls.TLSSession;
import nl.cypherpunk.statelearner.tls.Utils;

public class VPNSession {
	static final byte[] sidA = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0a};
	static final byte[] sidB = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b};
	static final byte[] sidC = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0c};

	// Random number generator used to generate sessionId and keys
	SecureRandom rand;
	boolean DEBUG = false;

	// Act as a VPN client
	boolean ROLE_CLIENT = true;

	// Refers to an already identified TLS session
	byte keyId = 0;

	// The list of the TLS session corresponding to this OpenVPN session.
	TLSSessionHandler TLSSessions;
	AckSession activeSession;

	// Material for encryption, decryption and authentification
	CipherSuite cipherSuite;
	String auth;
	String cipher;
	int method = 1;

	String proto = "udp";

	// TLS session associated with this VPNSession
	TLSSession tls;
	private int keyMethod;

	VPNSession() throws Exception {
		rand = new SecureRandom();
		tls = new TLSSession();
		TLSSessions = new TLSSessionHandler();
		setInitValues();
	}
	
	public void setProto(String proto) {
		if(proto.equalsIgnoreCase("tcp")) {
			this.proto = "tpc";
		} else {
			this.proto = "udp";
		}
	}
	
	public String getOptionString() {
		return "V4,dev-type tun,link-mtu 1571,tun-mtu 1500,proto " + proto.toUpperCase() +
		"v4,ifconfig 10.8.0.1 10.8.0.2,cipher " + cipher +
		",auth " + auth + ",keysize " + cipherSuite.getCypherLength() * 8 + "," +
		(cipher.equals("AES-256-CBC") ? "min-platform-entropy 0,": "")
		+ "tls-client";
	}

	public void setDebugging(boolean enable) {
		DEBUG = enable;
	}

	public void setTarget(String target) throws Exception {
		if(target.equals("server")) {
			ROLE_CLIENT = true;
		}
		else if(target.equals("client")) {
			ROLE_CLIENT = false;
		} else {
			throw new Exception("Unknown target");
		}
		tls.setTarget(target);
	}
	
	public void setCipher(String cipher) {
		this.cipher = cipher;
		if(this.cipher == null) {
			this.cipher = "BF-CBC";
		}
		if(this.cipher.equalsIgnoreCase("AES-256-CBC")) {
			cipherSuite.setCipherAlgo("AES");
		} else {
			cipherSuite.setCipherAlgo("Blowfish");
		}
	}
	
	public void setAuth(String auth) {
		this.auth = auth;
		if(this.auth == null) {
			this.auth = "SHA1";
		}
		if(this.auth.equalsIgnoreCase("SHA256")) {
			cipherSuite.setAuthAlgo("HmacSHA256");
		} else {
			cipherSuite.setAuthAlgo("HmacSHA1");
		}
	}

	public byte getKeyId() {
		return (byte) (keyId  & 0x07);
	}

	public void incrKeyId() {
		keyId = (byte) ((keyId + 1) % 8);
	}

	public void setSidA() {
		activeSession = this.TLSSessions.getSession(sidA);
	}

	public void setSidB() {
		activeSession = this.TLSSessions.getSession(sidB);
	}

	public void setSidC() {
		activeSession = this.TLSSessions.getSession(sidC);
	}

	/**
	 * Return the opcode of the packet from the type and the keyId
	 * @param the type of the packet
	 * @return the opcode
	 */
	public byte getOpcode(byte type) {
		//TODO put this function somewhere else ?
		return (byte) ((type << 0x03) | getKeyId());
	}

	public void genSession() {
		byte[] sessionId = new byte[8];
		// Ensure that the sessionId is a fresh one
		do {
			rand.nextBytes(sessionId); 
		} while (this.TLSSessions.getSession(sessionId) != null);
		this.activeSession = this.TLSSessions.addSession(sessionId);
	}
	
	private void initCipherSuite() {
		this.cipherSuite = new CipherSuite(rand);
		this.setAuth(this.auth);
		this.setCipher(this.cipher);
	}

	/**
	 * Set the initial values of the process.
	 * This method is used to reset the {@link VPNTestServiceUDP}.
	 * @throws Exception
	 */
	public void setInitValues() throws Exception {
		keyId = 0;
		this.initCipherSuite();
		this.TLSSessions.clear();
		this.genSession();
		this.TLSSessions.addSession(sidA);
		this.TLSSessions.addSession(sidB);
		this.TLSSessions.addSession(sidC);
		tls.setInitValues();

		// Load the keys
		if(ROLE_CLIENT) {
			tls.loadClientKey();
		} else {
			tls.loadServerKey();
		}
	}

	public void resetTLSSession() throws Exception {
		tls.setInitValues();
	}

	public void retrieveInitValues() throws Exception{
		tls.retrieveInitValues();
	}

	/**
	 * Receive a packet and build an output string
	 * @param input 
	 * @return
	 * @throws Exception
	 */
	public String receiveMessages(List<byte[]> msgList) throws Exception {
		String out = "";
		ByteArrayOutputStream tlsMsg = new ByteArrayOutputStream();

		for(byte[] input : msgList) {
			// Create the Message
			Message msg = new Message(input);
			if(DEBUG) {
				System.out.println("Received message: " + Utils.bytesToHex(msg.getPayload()));
			}

			ByteArrayInputStream payloadStream = new ByteArrayInputStream(msg.getPayload());
			switch (msg.getType()) {

			case Message.P_CONTROL_HARD_RESET_SERVER_V1:
				out += "SHRv1";
				HardReset hr1 = new HardReset(payloadStream);
				// Get the new remote session id
				this.TLSSessions.addRemoteSid(activeSession.getSessionId(), hr1.getSessionId());
				// Add the message to the Ack list
				this.TLSSessions.addPid(this.activeSession.getSessionId(), hr1.getPacketId());
				break;
				
			case Message.P_CONTROL_HARD_RESET_SERVER_V2:
				out += "SHRv2";
				HardReset hr2 = new HardReset(payloadStream);
				// Get the new remote session id
				this.TLSSessions.addRemoteSid(activeSession.getSessionId(), hr2.getSessionId());
				// Add the message to the Ack list
				this.TLSSessions.addPid(this.activeSession.getSessionId(), hr2.getPacketId());
				break;

			case Message.P_CONTROL_SOFT_RESET_V1:
				out += "SoftReset";
				SoftResetV1 sr = new SoftResetV1(payloadStream);
				// Add the message to the Ack list
				this.TLSSessions.addPid(this.activeSession.getSessionId(), sr.getPacketId());
				break;

			case Message.P_ACK_V1:
				out += "Ack";
				break;

			case Message.P_CONTROL_V1:
				ControlV1 ctrl = new ControlV1(payloadStream);
				tlsMsg.write(ctrl.getPayload());
				// Add the messages to the ACK list
				this.TLSSessions.addPid(this.activeSession.getSessionId(), ctrl.getPacketId());
				break;

			case Message.P_DATA_V1:
				DataV1 data = new DataV1(payloadStream, this.cipherSuite);
				if(DEBUG) System.out.println("Decrypted Data: " + Utils.bytesToHex(data.getPayload())); 
				if(ICMP.isPingReply(data.getPayload())) {
					out += "DataPingRep";
				} else {
					out += "Data";
				}
				break;
			}
		}
		// Process the TLS messages
		List<byte[]> applicationMessages = new ArrayList<>();
		if(tlsMsg.size() > 0) {
			out += "Tls:" + tls.receiveMessages(new ByteArrayInputStream(tlsMsg.toByteArray()), applicationMessages);
		}
		// Process the Application Messages
		for(byte[] app : applicationMessages) {
			if(DEBUG) System.out.println("ApplicationData: " + Utils.bytesToHex(app));
			this.receiveRemoteKey(new ByteArrayInputStream(app));
		}
		// Remove the Ack messages in the middle of responses
		if(!out.equals("Ack")) {
			out = out.replaceAll("Ack", "");
		}
		if(out.length() == 0) {
			out = "Empty";
		}
		return out;
	}

	public byte[] buildMessage(byte type, byte[] payload) throws Exception {
		byte opcode = getOpcode(type);
		Message msg = new Message(opcode, payload);

		if (DEBUG & !msg.isAck()) System.out.println("Sending message: " + Utils.bytesToHex(msg.getBytes()));

		// Increment the packet-id
		if(msg.isControl()) {
			this.activeSession.incrPacketId();
		}
		if(msg.isData()) {
			this.TLSSessions.incrDataPacketId();
		}

		return msg.getBytes();
	}

	private byte[] buildClientHardResetV1() throws Exception {
		keyId = 0;
		resetTLSSession();
		this.TLSSessions.predictRemoteSid(activeSession.getSessionId());

		HardReset hr = new HardReset(this.activeSession.getSessionId(), this.activeSession.getPacketId());
		return buildMessage(Message.P_CONTROL_HARD_RESET_CLIENT_V1, hr.getBytes());
	}

	public byte[] buildClientHardResetV2() throws Exception {
		keyId = 0;
		resetTLSSession();
		this.TLSSessions.predictRemoteSid(activeSession.getSessionId());

		HardReset hr = new HardReset(this.activeSession.getSessionId(), this.activeSession.getPacketId());
		return buildMessage(Message.P_CONTROL_HARD_RESET_CLIENT_V2, hr.getBytes());
	}
	
	/**
	 * Build a Hard Reset message but
	 * - Do not change the session-id
	 * - Do not reset the packet-id
	 * - Do not reset the TLS session
	 * - Do not reset the key-id
	 * @return the payload of the message
	 * @throws Exception
	 */
	public byte[] buildWeakCHRV1() throws Exception {
		HardReset hr = new HardReset(this.activeSession.getSessionId(), this.activeSession.getPacketId());
		return buildMessage(Message.P_CONTROL_HARD_RESET_CLIENT_V1, hr.getBytes());
	}


	private byte[] buildServerHardResetV1() throws Exception {
		keyId = 0;
		resetTLSSession();

		HardReset hr = new HardReset(this.activeSession.getSessionId(), this.activeSession.getPacketId());
		return buildMessage(Message.P_CONTROL_HARD_RESET_SERVER_V1, hr.getBytes());
	}

	public byte[] buildServerHardResetV2() throws Exception {
		keyId = 0;
		resetTLSSession();

		HardReset hr = new HardReset(this.activeSession.getSessionId(), this.activeSession.getPacketId());
		return buildMessage(Message.P_CONTROL_HARD_RESET_CLIENT_V2, hr.getBytes());
	}

	public byte[] buildClientHardResetRand() throws Exception {
		this.genSession();
		return buildClientHardResetV1();
	}

	public byte[] buildServerHardResetRand() throws Exception {
		this.genSession();
		return buildServerHardResetV1();
	}

	public byte[] buildClientHardResetSidA() throws Exception {
		this.activeSession = this.TLSSessions.getSession(sidA);
		this.activeSession.reset();
		return buildClientHardResetV1();
	}

	public byte[] buildClientHardResetSidB() throws Exception {
		this.activeSession = this.TLSSessions.getSession(sidB);
		this.activeSession.reset();
		return buildClientHardResetV1();
	}

	public byte[] buildClientHardResetSidC() throws Exception {
		this.activeSession = this.TLSSessions.getSession(sidC);
		this.activeSession.reset();
		return buildClientHardResetV1();
	}

	public byte[] buildSoftResetV1() throws Exception {
		incrKeyId();
		resetTLSSession();
		this.activeSession.resetPacketId();

		SoftResetV1 hr = new SoftResetV1(this.activeSession.getSessionId(), this.activeSession.getPacketId());
		return buildMessage(Message.P_CONTROL_SOFT_RESET_V1, hr.getBytes());
	}

	/**
	 * Build all the waiting acknowledgment messages for this OpenVPN session
	 * 
	 * Return null if there is no message to acknowledge
	 * 
	 * @throws Exception
	 */
	public List<byte[]> buildAck() throws Exception {
		List<Ack> ackList = this.TLSSessions.getAckList();
		if(ackList.isEmpty()) {
			return null;
		}
		List<byte[]> output = new ArrayList<>();
		for(Ack ack : ackList) {
			output.add(buildMessage(Message.P_ACK_V1, ack.getBytes()));
		}
		this.TLSSessions.clearAckList();
		if (DEBUG) System.out.println("ACKSent");
		return output;
	}

	public byte[] buildClientHelloRSA() throws Exception {
		byte[] payload = tls.buildClientHelloRSA();
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildClientHelloAll() throws Exception {
		byte[] payload = tls.buildClientHelloAll();
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildClientKeyExchange() throws Exception {
		byte[] payload = tls.buildClientKeyExchange();
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildEmptyCertificate() throws Exception {
		byte[] payload = tls.buildEmptyCertificate();
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildClientCertificate() throws Exception {
		byte[] payload = tls.buildClientCertificate();
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildClientCertificateVerify() throws IOException, Exception {
		byte[] payload = tls.buildClientCertificateVerify();
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildChangeCipherSpec() throws Exception {
		byte[] payload = tls.buildChangeCipherSpec();
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildFinished() throws Exception {
		byte[] payload = tls.buildFinished();
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildApplicationData() throws Exception {
		byte[] payload = tls.buildApplicationData();
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildExchangeKeyV1() throws Exception {
		byte[] tlsPayload = sendLocalKey1();
		byte[] payload = tls.buildApplicationData(tlsPayload);
		this.keyMethod = 1;
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildExchangeKeyV2() throws Exception {
		byte[] tlsPayload = sendLocalKey2();
		byte[] payload = tls.buildApplicationData(tlsPayload);
		this.keyMethod = 2;
		ControlV1 msg = new ControlV1(this.activeSession.getSessionId(), this.activeSession.getPacketId(), payload);
		return buildMessage(Message.P_CONTROL_V1, msg.getBytes());
	}

	public byte[] buildDataV1PingRequest() throws Exception {
		ICMPRequest ping = new ICMPRequest();
		DataV1 msg = new DataV1(this.activeSession.getDataPacketId(), ping.getBytes());
		return buildMessage(Message.P_DATA_V1, msg.encrypt(cipherSuite.getWriteCipher(), cipherSuite.getWriteMac()));
	}

	/**
	 * Build the payload of the OpenVPN key exchange message version 1.
	 * 
	 * TLS payload ciphertext (n bytes).
	 * byte   cypherLength; // Cipher key length in bytes (1 byte)
	 * byte[] cypher;       // Cipher key (n bytes)
	 * byte   hmacLength;   // HMAC key length in bytes (1 byte)
	 * byte[] hmac;         // HMAC key (n bytes)
	 * byte[] options;      // Options string (n bytes, null terminated, client/server options string should match)
	 * 
	 * @return the payload of the message that will be encapsulated in a TLS AppData message.
	 * @throws Exception
	 */
	private byte[] sendLocalKey1() throws Exception {
		ByteArrayOutputStream msg = new ByteArrayOutputStream();

		this.initCipherSuite();

		if(DEBUG) System.out.println("Write_Key: " + Utils.bytesToHex(cipherSuite.getReadKey()));
		if(DEBUG) System.out.println("Write_MAC_Key: " + Utils.bytesToHex(cipherSuite.getWriteKey()));

		msg.write(cipherSuite.cipherLength);
		msg.write(cipherSuite.hmacLength);
		msg.write(cipherSuite.writeKey);
		msg.write(cipherSuite.writeMacKey);

		msg.write(this.getOptionString().getBytes());
		// Null-terminate the string
		msg.write(0);
		return msg.toByteArray();
	}

	/**
	 * Build the payload of the OpenVPN key exchange message version 2.
	 * 
	 * Literal 0 (4 bytes).
	 * key_method type (1 byte) = 2.
	 * key_source structure:
	 *  - pre-master key (client only) (48 bytes)
	 *  - PRF seed for master secret (32 bytes)
	 *  - PRF seed for key expansion (32 bytes)
	 * options_string_length, including null (2 bytes).
	 * Options string (n bytes, null terminated, client/server options string must match).
	 * [The username/password data below is optional, record can end at this point.]
	 * username_string_length, including null (2 bytes).
	 * Username string (n bytes, null terminated).
	 * password_string_length, including null (2 bytes).
	 * Password string (n bytes, null terminated).
	 * 
	 * @return the payload of the message that will be encapsulated in a TLS AppData message.
	 * @throws Exception
	 */
	private byte[] sendLocalKey2() throws Exception {
		ByteArrayOutputStream msg = new ByteArrayOutputStream();

		this.initCipherSuite();

		// Write literal
		byte[] literal = {0,0,0,0};
		msg.write(literal);

		// Write key method
		msg.write(0x02);

		// Write pre-master key
		if(ROLE_CLIENT) {
			msg.write(cipherSuite.getPreMaster());
			msg.write(cipherSuite.getClientRand1());
			msg.write(cipherSuite.getClientRand2());
		} else {
			msg.write(cipherSuite.getServerRand1());
			msg.write(cipherSuite.getServerRand2());
		}

		String str = this.getOptionString();
		// Write option string
		msg.write(Utils.getbytes16(str.length() + 1));
		msg.write(str.getBytes());
		// Null-terminate the string
		msg.write(0);

		return msg.toByteArray();
	}

	private void receiveRemoteKey(InputStream input) throws Exception {
		if(this.keyMethod == 1) {
			receiveRemoteKey1(input);
		} else {
			receiveRemoteKey2(input);
		}
	}
	
	private void receiveRemoteKey1(InputStream input) throws Exception {
		byte cipherLen;
		byte hmacLen;
		cipherLen = (byte) input.read();
		hmacLen = (byte) input.read();

		if(cipherLen != cipherSuite.cipherLength || hmacLen != cipherSuite.hmacLength) {
			throw new IllegalArgumentException("Server key lengths do not match with client key length");
		}

		byte[] readKey = new byte[cipherLen];
		byte[] readMacKey = new byte[hmacLen];

		input.read(readKey);
		input.read(readMacKey);

		if(DEBUG) System.out.println("Read_Key: " + Utils.bytesToHex(readKey));
		if(DEBUG) System.out.println("Read_Mac_Key: " + Utils.bytesToHex(readMacKey));

		cipherSuite.setReadKey(readKey);
		cipherSuite.setReadMacKey(readMacKey);

		byte[] remoteString = new byte[input.available()];
		input.read(remoteString);
		if(DEBUG) System.out.println("RemoteString: " + new String(remoteString));
	}

	private void receiveRemoteKey2(InputStream input) throws Exception {
		// Discard literal
		input.skip(4);

		// Get key method
		if(input.read() != 2) {
			throw new IllegalArgumentException("Wrong key method");
		}

		if(!ROLE_CLIENT) {
			// Get pre-master key
			byte[] preMaster = new byte[48];
			input.read(preMaster);
			cipherSuite.setPreMaster(preMaster);

			// PRF seed for master secret
			byte[] masterSeed = new byte[32];
			input.read(masterSeed);
			cipherSuite.setClientRand1(masterSeed);

			// PRF seed for key expansion
			byte[] kExpSeed = new byte[32];
			input.read(kExpSeed);
			cipherSuite.setClientRand2(kExpSeed);
			
		} else {

			// PRF seed for master secret
			byte[] masterSeed = new byte[32];
			input.read(masterSeed);
			cipherSuite.setServerRand1(masterSeed);

			// PRF seed for key expansion
			byte[] kExpSeed = new byte[32];
			input.read(kExpSeed);
			cipherSuite.setServerRand2(kExpSeed);
		}

		byte[] stringLen = new byte[2];
		input.read(stringLen);
		byte[] remoteString = new byte[Utils.getuint16(stringLen[0], stringLen[1])];
		input.read(remoteString);
		if(DEBUG) System.out.println("RemoteString: " + new String(remoteString));

		cipherSuite.computeKeyBlock(this.activeSession.getSessionId(), this.activeSession.getRemoteSessionId());
		if(DEBUG) {
			System.out.println("Decrypt key: " + Utils.bytesToHex(cipherSuite.readKey));
			System.out.println("Decrypt HMAC: " + Utils.bytesToHex(cipherSuite.readMacKey));
			System.out.println("Encrypt key: " + Utils.bytesToHex(cipherSuite.writeKey));
			System.out.println("Encrypt HMAC: " + Utils.bytesToHex(cipherSuite.writeMacKey));
		}
	}
}
