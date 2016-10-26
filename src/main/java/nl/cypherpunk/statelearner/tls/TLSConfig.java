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

import java.io.IOException;

import nl.cypherpunk.statelearner.LearningConfig;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class TLSConfig extends LearningConfig {
	String alphabet;
	
	String target;
	String cmd;
	String cmd_version;
	String version;
	String keystore_filename;
	String keystore_password;
	
	String host;
	int port;
	
	boolean restart;
	boolean console_output;
	int timeout;
	
	public TLSConfig(String filename) throws IOException {
		super(filename);
	}
	
	public TLSConfig(LearningConfig config) {
		super(config);
	}	
	
	@Override
	public void loadProperties() {
		super.loadProperties();

		if(properties.getProperty("alphabet") != null)
			alphabet = properties.getProperty("alphabet");
		
		if(properties.getProperty("target").equalsIgnoreCase("client") || properties.getProperty("target").equalsIgnoreCase("server"))
			target = properties.getProperty("target").toLowerCase();
		
		if(properties.getProperty("cmd") != null)
			cmd = properties.getProperty("cmd");
		
		if(properties.getProperty("version") != null)
			version = properties.getProperty("version");
		else
			version = "tls12";
		
		if(properties.getProperty("cmd_version") != null)
			cmd_version = properties.getProperty("cmd_version");
		
		if(properties.getProperty("keystore_filename") != null)
			keystore_filename = properties.getProperty("keystore_filename");
		else
			keystore_filename = "keystore";

		if(properties.getProperty("keystore_password") != null)
			keystore_password = properties.getProperty("keystore_password");
		else
			keystore_password = "123456";
		
		if(properties.getProperty("host") != null)
			host = properties.getProperty("host");
		
		if(properties.getProperty("port") != null)
			port = Integer.parseInt(properties.getProperty("port"));

		if(properties.getProperty("console_output") != null)
			console_output = Boolean.parseBoolean(properties.getProperty("console_output"));
		else
			console_output = false;
		
		if(properties.getProperty("restart") != null)
			restart = Boolean.parseBoolean(properties.getProperty("restart"));
		else
			restart = false;
		
		if(properties.getProperty("timeout") != null)
			timeout = Integer.parseInt(properties.getProperty("timeout"));
	}

}
