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

import java.io.IOException;

import nl.cypherpunk.statelearner.LearningConfig;

public class SCConfig extends LearningConfig {
	String apdu_file;
	String alphabet;
	String prefix;
	
	public SCConfig(String filename) throws IOException {
		super(filename);
	}

	public SCConfig(LearningConfig config) {
		super(config);
	}

	@Override
	public void loadProperties() {
		super.loadProperties();

		if(properties.getProperty("apdu_file") != null)
			apdu_file = properties.getProperty("apdu_file");
		
		if(properties.getProperty("alphabet") != null)
			alphabet = properties.getProperty("alphabet");
		
		if(properties.getProperty("prefix") != null)
			prefix = properties.getProperty("prefix");
	}
}
