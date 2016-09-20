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

package nl.cypherpunk.statelearner.tls.messages;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.util.Arrays;

import nl.cypherpunk.statelearner.tls.TLS;
import nl.cypherpunk.statelearner.tls.Utils;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class ClientKeyExchange extends HandshakeMsg {
	byte[] exchangeKeys;
	
	public ClientKeyExchange(byte[] exchangeKeys) throws IOException {
		super(TLS.HANDSHAKE_MSG_TYPE_CLIENT_KEY_EXCHANGE, 0, new byte[] {});
		this.exchangeKeys = exchangeKeys;
		
		ByteArrayOutputStream payloadStream = new ByteArrayOutputStream();
		payloadStream.write(Utils.getbytes16(exchangeKeys.length));
		payloadStream.write(exchangeKeys);
		
		payload = payloadStream.toByteArray();
		length = payload.length;
	}
	
	public ClientKeyExchange(HandshakeMsg hs) {
		super(hs.getType(), hs.getLength(), hs.getPayload());
		
		int lenExchangeKeys = Utils.getuint16(payload[0], payload[1]);
		exchangeKeys = Arrays.copyOfRange(payload, 2, 2 + lenExchangeKeys);
	}
	
	public byte[] getExchangeKeys() {
		return exchangeKeys;
	}
}
