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

package nl.cypherpunk.statelearner.smartcard;

import java.util.Arrays;
import java.util.HashMap;

import net.automatalib.words.impl.SimpleAlphabet;
import nl.cypherpunk.statelearner.StateLearnerSUL;
import de.learnlib.api.SUL;

/**
 * SUL that makes use of the smartcard test service
 * 
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class SCSUL implements StateLearnerSUL<String, String> {
	SmartcardTestService scTestService;
	SimpleAlphabet<String> alphabet;
	String[] prefix = {};

	public SCSUL(HashMap<String, byte[][]> apduDictionary) throws Exception {
		// Initialise test service
		scTestService = new  SmartcardTestService(apduDictionary);
		alphabet = new SimpleAlphabet<String>(scTestService.getAPDUDictionary().keySet());
	}
	
	public SCSUL(SCConfig config) throws Exception {
		// Initialise test service
		scTestService = new SmartcardTestService();
		scTestService.loadAPDUDictionary(config.apdu_file);

		if(config.alphabet != null)
			alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));
		else
			alphabet = new SimpleAlphabet<String>(scTestService.getAPDUDictionary().keySet());

		if(config.prefix != null)
			prefix = config.prefix.split(" ");		
	}
	
	public SimpleAlphabet<String> getAlphabet() {
		// Get alphabet from the SmartcardService's APDU dictionary
		return alphabet;
	}

	public String step(String symbol) {
		String result = "";
		try {
			// Process symbol and return result
			result = scTestService.processCommand(symbol);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	public boolean canFork() {
		return false;
	}

	public SUL<String, String> fork() throws UnsupportedOperationException {
		throw new UnsupportedOperationException("Cannot fork SCSUL");
	}

	public void pre() {
		try {
			// Reset test service
			scTestService.reset();
			
			for(String cmd: prefix) {
				scTestService.sendCommand(cmd);
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}		
	}
	
	public void post() {
		// Nothing to cleanup
	}
}