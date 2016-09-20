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

import java.io.IOException;
import java.io.InputStream;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class Alert {
	private byte level;
	private byte description;
	
	public Alert(InputStream msg) throws IOException {
		level = (byte)(0xFF & msg.read());
		description = (byte)(0xFF & msg.read());		
	}
	
	public Alert(byte level, byte description) {
		this.level = level;
		this.description = description;
	}
	
	public byte[] getBytes() {
		return new byte[] {level, description};
	}
	
	public byte getLevel() {
		return level;
	}
	
	public byte getDescription() {
		return description;
	}
}
