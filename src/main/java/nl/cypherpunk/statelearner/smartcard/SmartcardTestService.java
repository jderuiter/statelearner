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

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;
import javax.swing.JOptionPane;

import nl.cypherpunk.statelearner.Utils;

public class SmartcardTestService {
	protected CardTerminal terminal;
	protected Card card;
	protected CardChannel channel;
	
	private HashMap<String, byte[][]> apduDictionary;
		
	public SmartcardTestService() throws Exception {
		System.setProperty("sun.security.smartcardio.t0GetResponse", "false");
		System.setProperty("sun.security.smartcardio.t1GetResponse", "false");
		
		//System.out.println("JRE version: " + System.getProperty("java.version"));
		//System.out.println("JRE vendor: " + System.getProperty("java.vendor"));
		
		//System.out.println("JRE spec version: " + System.getProperty("java.specification.version"));
		//System.out.println("JRE spec vendor: " + System.getProperty("java.specification.vendor"));
		
		// Get list of card readers
		List<CardTerminal> terminals = TerminalFactory.getDefault().terminals().list();
		
		if(terminals.size() == 0) {
			throw new Exception("No readers found.");
		}
		
		// Ask user to select a card reader to connect to
		terminal = (CardTerminal)JOptionPane.showInputDialog(null, "Reader", "Select a reader", JOptionPane.QUESTION_MESSAGE, null, terminals.toArray(), terminals.get(0));
		
		if(terminal == null) {
			throw new Exception("No reader selected.");
		}

		System.err.println("Selected reader: " + terminal.toString());
		
		// Connect to card in selected reader
		card = terminal.connect("*");
		channel = card.getBasicChannel();
		
		System.err.println("Connected to card");
	}
	
	public SmartcardTestService(HashMap<String, byte[][]> apduDictionary) throws Exception {
		this();
		setAPDUDictionary(apduDictionary);
	}
	
	public void setAPDUDictionary(HashMap<String, byte[][]> apduDictionary) {
		// Store dictionary containing APDUs locally
		this.apduDictionary = apduDictionary;
	}
	
	public HashMap<String, byte[][]> getAPDUDictionary() {
		return apduDictionary;
	}
	
	public void loadAPDUDictionary(String apdu_file) throws IOException {
		apduDictionary = new HashMap<String, byte[][]>();
		
		// Read APDUs from file
		BufferedReader reader = new BufferedReader(new FileReader(apdu_file));
		String line;
		
		while ((line = reader.readLine()) != null) {
			String[] row = line.split(";", 2);
			if(row.length == 2) {
				String[] apdus = row[1].split(",");
				byte[][] raw_apdus = new byte[apdus.length][];
				for(int i = 0; i < apdus.length; i++) {
					raw_apdus[i] = Utils.hexToBytes(apdus[i]);
				}
				apduDictionary.put(row[0], raw_apdus);
			}
		}
		
		reader.close();
	}
	
	public void reset() throws CardException, InterruptedException {
		// Reset connection with card
		card.disconnect(true);//TODO Behaviour of parameter is opposite to API for OpenJDK 1.7? http://bugs.java.com/bugdatabase/view_bug.do?bug_id=7047033
		
		// Java 1.7 and lower
		//card.disconnect(false);
		
		// Sleep to give the card time to reset
		//Thread.sleep(1000);// Only necessary if reset doesn't work properly
		
		// Connect to card
		card = terminal.connect("*");
		channel = card.getBasicChannel();
	}
	
	public ResponseAPDU sendAPDU(byte[] apdu) throws CardException {
		// Send APDU to card and get response
		CommandAPDU commandAPDU = new CommandAPDU(apdu);
		ResponseAPDU response = this.channel.transmit(commandAPDU);
				
		while(response.getSW1() == 0x61 || response.getSW1() == 0x6C) {
			if(response.getSW1() == 0x61) {
				commandAPDU = new CommandAPDU(0x00, 0xC0, 0x00, 0x00, response.getSW2());
				response = channel.transmit(commandAPDU);
			}
			else if(response.getSW1() == 0x6C) {
				commandAPDU = new CommandAPDU(commandAPDU.getCLA(), commandAPDU.getINS(), commandAPDU.getP1(), commandAPDU.getP2(), response.getSW2());
				response = channel.transmit(commandAPDU);
			}
		}
		
		return response;
	}
	
	public ResponseAPDU[] sendCommand(String command) throws Exception {
		// Look up APDU corresponding with given command
		byte[][] payloads = apduDictionary.get(command);
		
		if(payloads == null) {
			throw new Exception("Unknown command");
		}
		
		ResponseAPDU[] responses = new ResponseAPDU[payloads.length];
		
		for(int i = 0; i < payloads.length; i++) {
			responses[i] = sendAPDU(payloads[i]);
		}
		
		// Return responses from last command
		return responses;		
	}
	
	public String processCommand(String command) throws Exception {
		ResponseAPDU[] responses = sendCommand(command);
		List<String> outputs = new ArrayList<String>();
		
		for(ResponseAPDU response: responses) {
			// Return abstract response from card
			String returnValue = "SW:" + Integer.toHexString(response.getSW());
		
			if(response.getData().length > 0) {
				String strData = Utils.bytesToHex(response.getData());

				if(strData.contains("9F27")) {
					returnValue += ",AC:" + strData.substring(strData.indexOf("9F27")+6, strData.indexOf("9F27")+8);
				}
				else if(command.contains("GENERATE_AC")) {
					// Visa card?
					returnValue += ",AC:" + strData.substring(4, 6);
				}

				returnValue += ",Len:" + response.getData().length;
			}
			
			outputs.add(returnValue);
		}
		
		//TODO Add support to select part of data to be included in output
		return String.join("/", outputs);
	}
		
	public static void main(String[] args) throws Exception {
		if(args.length < 2) {
			System.out.println("Usage: " + args[0] + " <APDU file> <APDU list>");
			System.exit(0);
		}
		
		SmartcardTestService sc = new SmartcardTestService();
		sc.loadAPDUDictionary(args[0]);
		
		String[] commands = args[1].split(";");
		List<String> outputs = new ArrayList<String>();
		
		for(String command: commands) {
			ResponseAPDU[] responses = sc.sendCommand(command.trim());
			List<String> output = new ArrayList<String>();

			for(ResponseAPDU response: responses) {
				String resp = "SW:" + Integer.toHexString(response.getSW());

				if(response.getData().length > 0) {
					resp += ",Data:" + Utils.bytesToHex(response.getData());
				}
				
				output.add(resp);
			}
			
			outputs.add(String.join("/", output));
		}
		
		System.out.println(String.join(";", outputs));
	}
}
