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
abstract public class TLS {
	public final static byte CONTENT_TYPE_CCS = 0x14;
	public final static byte CONTENT_TYPE_ALERT = 0x15;
	public final static byte CONTENT_TYPE_HANDSHAKE = 0x16;
	public final static byte CONTENT_TYPE_APPLICATION = 0x17;
	public final static byte CONTENT_TYPE_HEARTBEAT = 0x18;

	public final static byte HANDSHAKE_MSG_TYPE_HELLO_REQUEST = 0x00;
	public final static byte HANDSHAKE_MSG_TYPE_CLIENT_HELLO = 0x01;
	public final static byte HANDSHAKE_MSG_TYPE_SERVER_HELLO = 0x02;
	public final static byte HANDSHAKE_MSG_TYPE_CERTIFICATE = 0x0B;
	public final static byte HANDSHAKE_MSG_TYPE_SERVER_KEY_EXCHANGE = 0x0C;
	public final static byte HANDSHAKE_MSG_TYPE_CERTIFICATE_REQUEST = 0x0D;
	public final static byte HANDSHAKE_MSG_TYPE_SERVER_HELLO_DONE = 0x0E;
	public final static byte HANDSHAKE_MSG_TYPE_CERTIFICATE_VERIFY = 0x0F;
	public final static byte HANDSHAKE_MSG_TYPE_CLIENT_KEY_EXCHANGE = 0x10;
	public final static byte HANDSHAKE_MSG_TYPE_FINISHED = 0x14;

	public final static byte HEARTBEAT_MSG_TYPE_REQUEST = 0x01;
	public final static byte HEARTBEAT_MSG_TYPE_RESPONSE = 0x02;

	public final static byte[] EXTENSION_TYPE_STATUS_REQUEST = {0x00, 0x05};
	public final static byte[] EXTENSION_TYPE_HEARTBEAT = {0x00, 0x0F};
	public final static byte[] EXTENSION_TYPE_RENEGOGIATION_INFO = {(byte)0xFF, 0x01};
	
	public final static byte HEARTBEAT_EXTENSION_PEER_ALLOWED_TO_SEND = 0x01;
	public final static byte HEARTBEAT_EXTENSION_PEER_NOT_ALLOWED_TO_SEND = 0x02;
	
	protected ProtocolVersion protocolVersion = ProtocolVersion.EMPTY;
	
	public ProtocolVersion getProtocolVersion() {
		return protocolVersion;
	}
	
	abstract public byte[] masterSecret(byte[] preMasterSecret, byte[] serverRandom, byte[] clientRandom) throws Exception;
	abstract public byte[] keyblock(byte[] masterSecret, byte[] serverRandom, byte[] clientRandom) throws Exception;	
	abstract public byte[] verifyDataClient(byte[] masterSecret, byte[] handshakeMessages) throws Exception;
	abstract public byte[] verifyDataServer(byte[] masterSecret, byte[] handshakeMessages) throws Exception;
}
