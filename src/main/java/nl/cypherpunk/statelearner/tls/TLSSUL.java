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

import java.util.Arrays;

import net.automatalib.words.impl.SimpleAlphabet;
import nl.cypherpunk.statelearner.StateLearnerSUL;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class TLSSUL implements StateLearnerSUL<String, String> {
	SimpleAlphabet<String> alphabet;
	TLSTestService tls;
	
	public TLSSUL(TLSConfig config) throws Exception {
		alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));
		
		tls = new TLSTestService();
		
		tls.setTarget(config.target);
		tls.setHost(config.host);
		tls.setPort(config.port);
		tls.setCommand(config.cmd);
		tls.setRequireRestart(config.restart);
		tls.setReceiveMessagesTimeout(config.timeout);
		tls.setKeystore(config.keystore_filename, config.keystore_password);
		tls.setConsoleOutput(config.console_output);
		
		if(config.version.equals("tls10")) {
			tls.useTLS10();
		}
		else {
			tls.useTLS12();
		}
		
		tls.start();
	}
	
	public SimpleAlphabet<String> getAlphabet() {
		return alphabet;
	}	

	public boolean canFork() {
		return false;
	}
	
	@Override
	public String step(String symbol) {
		String result = null;
		try {
			result = tls.processSymbol(symbol);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	@Override
	public void pre() {
		try {
			tls.reset();
		} catch (Exception e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}	
	}

	@Override
	public void post() {
	}
	
}
