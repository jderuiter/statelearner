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

import java.io.IOException;

import nl.cypherpunk.statelearner.LearningConfig;

public class VPNConfig extends LearningConfig {
	String alphabet;
	
	// The version of the protocol (openvpn-nl or openvpn)
	String version;
	
	// Client or server
	String target;
	
	// Network addresses
	String local;
	String remote;
	int localPort;
	int remotePort;
	
	String cmd;
	String proto;
	String dev;
	String auth;
	String cipher;
	String method;
	
	public VPNConfig(String filename) throws IOException {
		super(filename);
	}
	
	public VPNConfig(LearningConfig config) {
		super(config);
	}	
	
	@Override
	public void loadProperties() { 
		super.loadProperties();
		
		if(properties.getProperty("alphabet") != null) {
			alphabet = properties.getProperty("alphabet");
		}
		
		if(properties.getProperty("version") != null) {
			version = properties.getProperty("version");
		} else {
			version = "openvpn";
		}
		
		if(properties.getProperty("target").equalsIgnoreCase("client") || properties.getProperty("target").equalsIgnoreCase("server")) {
			target = properties.getProperty("target").toLowerCase();
		} else {
			target = "server";
		}
		
		if(properties.getProperty("cmd") != null) {
			cmd = properties.getProperty("cmd");
		} else {
			cmd = "";
		}
		
		if(properties.getProperty("local") != null) {
			local = properties.getProperty("local");
		} else {
			local = "172.16.5.1";
		}
		
		if(properties.getProperty("remote") != null) {
			remote = properties.getProperty("remote");
		} else {
			remote = "172.16.5.128";
		}
		
		if(properties.getProperty("localPort") != null) {
			localPort = Integer.parseInt(properties.getProperty("localPort"));
		} else {
			localPort = 1194;
		}
		
		if(properties.getProperty("remotePort") != null) {
			remotePort = Integer.parseInt(properties.getProperty("remotePort"));
		} else {
			remotePort = 1194;
		}
		
		if(properties.getProperty("proto") != null) {
			proto = properties.getProperty("proto");
		} else {
			proto = "udp";
		}
		
		if(properties.getProperty("dev") != null) {
			dev = properties.getProperty("dev");
		} else {
			dev = "tun";
		}

		if(properties.getProperty("auth") != null) {
			auth = properties.getProperty("auth");
		} else if(version.equals("openvpn-nl")) {
			auth = "SHA256";
		} else {
			auth = "SHA1";
		}
		
		if(properties.getProperty("cipher") != null) {
			cipher = properties.getProperty("cipher");
		} else if(version.equals("openvpn-nl")) {
			cipher = "AES-256-CBC";
		} else {
			cipher = "BF-CBC";
		}
		
		if(properties.getProperty("method") != null) {
			method = properties.getProperty("method");
		} else {
			method = "1";
		}
	}
}