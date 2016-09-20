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

import nl.cypherpunk.statelearner.tls.TLS;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class ServerHelloDone extends HandshakeMsg {
	public ServerHelloDone() {
		super(TLS.HANDSHAKE_MSG_TYPE_SERVER_HELLO_DONE, 0, new byte[] {});
	}
}
