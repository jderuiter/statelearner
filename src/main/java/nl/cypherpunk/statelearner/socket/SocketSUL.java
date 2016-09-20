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

package nl.cypherpunk.statelearner.socket;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.util.Arrays;

import net.automatalib.words.impl.SimpleAlphabet;
import de.learnlib.api.SUL;

public class SocketSUL implements SUL<String, String> {
	SimpleAlphabet<String> alphabet;
	Socket socket;
	BufferedWriter out;
	BufferedReader in;

	public SocketSUL(SocketConfig config) throws Exception {
		alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));
		
		// Initialise test service
		socket = new Socket(config.hostname, config.port);
		out = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
		in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
	}
	
	public SimpleAlphabet<String> getAlphabet() {
		return alphabet;
	}

	public String step(String symbol) {
		String result = "";
		try {
			// Process symbol and return result
			System.out.println("Sending symbol: " + symbol);
			out.write(symbol + "\n");
			out.flush();
			
			result = in.readLine();
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	public boolean canFork() {
		return false;
	}

	public SUL<String, String> fork() throws UnsupportedOperationException {
		throw new UnsupportedOperationException("Cannot fork SocketSUL");
	}

	public void pre() {
		try {
			// Reset test service
			System.out.println("Sending symbol: RESET");
			out.write("RESET\n");
			out.flush();
			
			//TODO Do we need to check the response?
			in.readLine();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}		
	}
	
	public void post() {
		// Nothing to cleanup
	}
}