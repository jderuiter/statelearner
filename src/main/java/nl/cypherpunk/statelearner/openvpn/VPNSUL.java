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

import java.net.SocketException;
import java.util.Arrays;

import de.learnlib.api.SUL;
import net.automatalib.words.impl.SimpleAlphabet;


public class VPNSUL implements SUL<String, String> {
	SimpleAlphabet<String> alphabet;
	VPNTestService vpn;
	
	public VPNSUL(VPNConfig config) throws Exception {
		alphabet = new SimpleAlphabet<String>(Arrays.asList(config.alphabet.split(" ")));
		
		if(config.proto.equals("tcp")) {
			vpn = new VPNTestServiceTCP();
		} else {
			vpn = new VPNTestServiceUDP();
		}
		vpn.setTarget(config.target);
		vpn.setLocal(config.local);
		vpn.setRemote(config.remote);
		vpn.setLocalPort(config.localPort);
		vpn.setRemotePort(config.remotePort);
		
		vpn.setAuth(config.auth);
		vpn.setCipher(config.cipher);
		if(config.cmd.equals("")) {
			vpn.setCommand(config.version, config.proto, config.method);
		} else {
			vpn.setCommand(config.cmd);
		}
		
		try {
			vpn.start();
		} catch(SocketException e) {
			e.printStackTrace();
			vpn.closeSocket();
			vpn.close();
		}
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
			result = vpn.processSymbol(symbol);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}

	@Override
	public void pre() {
		try {
			vpn.reset();
		} catch (Exception e) {
			e.printStackTrace();
			System.exit(0);
		}
	}

	@Override
	public void post() {
	}
}
