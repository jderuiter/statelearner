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

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class Extension {
	byte[] type;
	byte[] payload;
	
	public Extension(byte[] type, byte[] payload) {
		this.type = type;
		this.payload = payload;
	}
	
	public byte[] getBytes() throws IOException {
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		out.write(type);
		out.write(Utils.getbytes16(payload.length));
		out.write(payload);
		
		return out.toByteArray();
	}
}
