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

package nl.cypherpunk.statelearner;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collection;
import java.util.Random;
import java.util.logging.ConsoleHandler;
import java.util.logging.FileHandler;
import java.util.logging.Level;
import java.util.logging.SimpleFormatter;

import de.learnlib.acex.analyzers.AcexAnalyzers;
import de.learnlib.algorithms.dhc.mealy.MealyDHC;
import de.learnlib.algorithms.kv.mealy.KearnsVaziraniMealy;
import de.learnlib.algorithms.lstargeneric.mealy.ExtensibleLStarMealyBuilder;
import de.learnlib.algorithms.malerpnueli.MalerPnueliMealy;
import de.learnlib.algorithms.rivestschapire.RivestSchapireMealy;
import de.learnlib.algorithms.ttt.base.TTTState;
import de.learnlib.algorithms.ttt.mealy.TTTLearnerMealy;
import de.learnlib.api.EquivalenceOracle;
import de.learnlib.api.LearningAlgorithm;
import de.learnlib.api.SUL;
import de.learnlib.cache.mealy.MealyCacheOracle;
import de.learnlib.counterexamples.AcexLocalSuffixFinder;
import de.learnlib.eqtests.basic.RandomWordsEQOracle.MealyRandomWordsEQOracle;
import de.learnlib.eqtests.basic.WMethodEQOracle;
import de.learnlib.eqtests.basic.WpMethodEQOracle;
import de.learnlib.logging.LearnLogger;
import de.learnlib.oracles.CounterOracle.MealyCounterOracle;
import de.learnlib.oracles.DefaultQuery;
import de.learnlib.oracles.SULOracle;
import de.learnlib.statistics.Counter;
import de.learnlib.statistics.SimpleProfiler;
import net.automatalib.automata.transout.MealyMachine;
import net.automatalib.util.graphs.dot.GraphDOT;
import net.automatalib.words.Word;
import net.automatalib.words.impl.SimpleAlphabet;
import nl.cypherpunk.statelearner.ModifiedWMethodEQOracle.MealyModifiedWMethodEQOracle;
import nl.cypherpunk.statelearner.smartcard.SCConfig;
import nl.cypherpunk.statelearner.smartcard.SCSUL;
import nl.cypherpunk.statelearner.socket.SocketConfig;
import nl.cypherpunk.statelearner.socket.SocketSUL;
import nl.cypherpunk.statelearner.tls.TLSConfig;
import nl.cypherpunk.statelearner.tls.TLSSUL;
import nl.cypherpunk.statelearner.LogOracle.MealyLogOracle;

/**
 * @author Joeri de Ruiter (joeri@cs.ru.nl)
 */
public class Learner {
	LearningConfig config;
	SimpleAlphabet<String> alphabet;
	SUL<String, String> sul;
	SULOracle<String, String> memOracle;
	MealyLogOracle<String, String> logMemOracle;
	MealyCounterOracle<String, String> statsMemOracle;
	MealyCacheOracle<String, String> cachedMemOracle;
	MealyCounterOracle<String, String> statsCachedMemOracle;	
	LearningAlgorithm<MealyMachine<?, String, ?, String>, String, Word<String>> learningAlgorithm;

	SULOracle<String, String> eqOracle;
	MealyLogOracle<String, String> logEqOracle;
	MealyCounterOracle<String, String> statsEqOracle;
	MealyCacheOracle<String, String> cachedEqOracle;
	MealyCounterOracle<String, String> statsCachedEqOracle;
	EquivalenceOracle<MealyMachine<?, String, ?, String>, String, Word<String>> equivalenceAlgorithm;
	
	public Learner(LearningConfig config) throws Exception {
		this.config = config;
		
		// Create output directory if it doesn't exist
		Path path = Paths.get(config.output_dir);
		if(Files.notExists(path)) {
			Files.createDirectories(path);
		}
		
		configureLogging(config.output_dir);
		
		LearnLogger log = LearnLogger.getLogger(Learner.class.getSimpleName());

		// Check the type of learning we want to do and create corresponding configuration and SUL
		if(config.type == LearningConfig.TYPE_SMARTCARD) {
			log.log(Level.INFO, "Using smartcard SUL");	
			
			// Create the smartcard SUL
			sul = new SCSUL(new SCConfig(config));
			alphabet = ((SCSUL)sul).getAlphabet();			
		}
		else if(config.type == LearningConfig.TYPE_SOCKET) {
			log.log(Level.INFO, "Using socket SUL");
			
			// Create the socket SUL
			sul = new SocketSUL(new SocketConfig(config));
			alphabet = ((SocketSUL)sul).getAlphabet();			
		}
		else if(config.type == LearningConfig.TYPE_TLS) {
			log.log(Level.INFO, "Using TLS SUL");
			
			// Create the TLS SUL
			sul = new TLSSUL(new TLSConfig(config));
			alphabet = ((TLSSUL)sul).getAlphabet();			
		}
		
		loadLearningAlgorithm(config.learning_algorithm, alphabet, sul);
		loadEquivalenceAlgorithm(config.eqtest, alphabet, sul);
	}
	
	public void loadLearningAlgorithm(String algorithm, SimpleAlphabet<String> alphabet, SUL<String, String> sul) throws Exception {
		// Create the membership oracle
		//memOracle = new SULOracle<String, String>(sul);
		// Add a logging oracle
		logMemOracle = new MealyLogOracle<String, String>(sul, LearnLogger.getLogger("learning_queries"));		
        // Count the number of queries actually sent to the SUL
		statsMemOracle = new MealyCounterOracle<String, String>(logMemOracle, "membership queries to SUL");
		// Use cache oracle to prevent double queries to the SUL
		//cachedMemOracle = MealyCacheOracle.createDAGCacheOracle(alphabet, statsMemOracle);
        // Count the number of queries to the cache
		statsCachedMemOracle = new MealyCounterOracle<String, String>(statsMemOracle, "membership queries to cache");
		
		// Instantiate the selected learning algorithm
		switch(algorithm.toLowerCase()) {
			case "lstar":
				learningAlgorithm = new ExtensibleLStarMealyBuilder<String, String>().withAlphabet(alphabet).withOracle(statsCachedMemOracle).create();
				break;
				 	
			case "dhc":
				learningAlgorithm = new MealyDHC<String, String>(alphabet, statsCachedMemOracle);
				break;
				
			case "kv":
				learningAlgorithm = new KearnsVaziraniMealy<String, String>(alphabet, statsCachedMemOracle, true, AcexAnalyzers.BINARY_SEARCH);
				break;
				
			case "ttt":
				AcexLocalSuffixFinder suffixFinder = new AcexLocalSuffixFinder(AcexAnalyzers.BINARY_SEARCH, true, "Analyzer");
				learningAlgorithm = new TTTLearnerMealy<String, String>(alphabet, statsCachedMemOracle, suffixFinder);
				break;
				
			case "mp":
				learningAlgorithm = new MalerPnueliMealy<String, String>(alphabet, statsCachedMemOracle);
				break;
				
			case "rs":
				learningAlgorithm = new RivestSchapireMealy<String, String>(alphabet, statsCachedMemOracle);
				break;

			default:
				throw new Exception("Unknown learning algorithm " + config.learning_algorithm);
		}		
	}
	
	public void loadEquivalenceAlgorithm(String algorithm, SimpleAlphabet<String> alphabet, SUL<String, String> sul) throws Exception {
		//TODO We could combine the two cached oracle to save some queries to the SUL
		// Create the equivalence oracle
		//eqOracle = new SULOracle<String, String>(sul);
		// Add a logging oracle
		logEqOracle = new MealyLogOracle<String, String>(sul, LearnLogger.getLogger("equivalence_queries"));
		// Add an oracle that counts the number of queries
		statsEqOracle = new MealyCounterOracle<String, String>(logEqOracle, "equivalence queries to SUL");
		// Use cache oracle to prevent double queries to the SUL
		//cachedEqOracle = MealyCacheOracle.createDAGCacheOracle(alphabet, statsEqOracle);
        // Count the number of queries to the cache
		statsCachedEqOracle = new MealyCounterOracle<String, String>(statsEqOracle, "equivalence queries to cache");
		
		// Instantiate the selected equivalence algorithm
		switch(algorithm.toLowerCase()) {
			case "wmethod":
				equivalenceAlgorithm = new WMethodEQOracle.MealyWMethodEQOracle<String, String>(config.max_depth, statsCachedEqOracle);
				break;

			case "modifiedwmethod":
				equivalenceAlgorithm = new MealyModifiedWMethodEQOracle<String, String>(config.max_depth, statsCachedEqOracle);
				break;
				
			case "wpmethod":
				equivalenceAlgorithm = new WpMethodEQOracle.MealyWpMethodEQOracle<String, String>(config.max_depth, statsCachedEqOracle);
				break;
				
			case "randomwords":
				equivalenceAlgorithm = new MealyRandomWordsEQOracle<String, String>(statsCachedEqOracle, config.min_length, config.max_length, config.nr_queries, new Random(config.seed));
				break;
				
			default:
				throw new Exception("Unknown equivalence algorithm " + config.eqtest);
		}	
	}
	
	public void learn() throws IOException, InterruptedException {
		LearnLogger log = LearnLogger.getLogger(Learner.class.getSimpleName());

		log.log(Level.INFO, "Using learning algorithm " + learningAlgorithm.getClass().getSimpleName());
		log.log(Level.INFO, "Using equivalence algorithm " + equivalenceAlgorithm.getClass().getSimpleName());
		
		log.log(Level.INFO, "Starting learning");
		
		SimpleProfiler.start("Total time");
		
		boolean learning = true;
		Counter round = new Counter("Rounds", "");

		round.increment();
		log.logPhase("Starting round " + round.getCount());
		SimpleProfiler.start("Learning");
		learningAlgorithm.startLearning();
		SimpleProfiler.stop("Learning");

		MealyMachine<?, String, ?, String> hypothesis = learningAlgorithm.getHypothesisModel();
		
		while(learning) {
			// Write outputs
			writeDotModel(hypothesis, alphabet, config.output_dir + "/hypothesis_" + round.getCount() + ".dot");

			// Search counter-example
			SimpleProfiler.start("Searching for counter-example");
			DefaultQuery<String, Word<String>> counterExample = equivalenceAlgorithm.findCounterExample(hypothesis, alphabet);	
			SimpleProfiler.stop("Searching for counter-example");
			
			if(counterExample == null) {
				// No counter-example found, so done learning
				learning = false;
				
				// Write outputs
				writeDotModel(hypothesis, alphabet, config.output_dir + "/learnedModel.dot");
				//writeAutModel(hypothesis, alphabet, config.output_dir + "/learnedModel.aut");
			}
			else {
				// Counter example found, update hypothesis and continue learning
				log.logCounterexample("Counter-example found: " + counterExample.toString());
				//TODO Add more logging
				round.increment();
				log.logPhase("Starting round " + round.getCount());
				
				SimpleProfiler.start("Learning");
				learningAlgorithm.refineHypothesis(counterExample);
				SimpleProfiler.stop("Learning");
				
				hypothesis = learningAlgorithm.getHypothesisModel();
			}
		}

		SimpleProfiler.stop("Total time");
		
		// Output statistics
		log.log(Level.INFO, "-------------------------------------------------------");
		log.log(Level.INFO, SimpleProfiler.getResults());
		log.log(Level.INFO, round.getSummary());
		log.log(Level.INFO, statsMemOracle.getStatisticalData().getSummary());
		log.log(Level.INFO, statsCachedMemOracle.getStatisticalData().getSummary());
		log.log(Level.INFO, statsEqOracle.getStatisticalData().getSummary());
		log.log(Level.INFO, statsCachedEqOracle.getStatisticalData().getSummary());
		log.log(Level.INFO, "States in final hypothesis: " + hypothesis.size());		
	}
	
	public static void writeAutModel(MealyMachine<?, String, ?, String> model, SimpleAlphabet<String> alphabet, String filename) throws FileNotFoundException {
		// Make use of LearnLib's internal representation of states as integers
		@SuppressWarnings("unchecked")
		MealyMachine<Integer, String, ?, String> tmpModel = (MealyMachine<Integer, String, ?, String>) model;
		
		// Write output to aut-file
		File autFile = new File(filename);
		PrintStream psAutFile = new PrintStream(autFile);
		
		int nrStates = model.getStates().size();
		// Compute number of transitions, assuming the graph is complete
		int nrTransitions = nrStates * alphabet.size();
		
		psAutFile.println("des(" + model.getInitialState().toString() + "," + nrTransitions + "," + nrStates + ")");
		
		Collection<Integer> states = tmpModel.getStates();

		for(Integer state: states) {
			for(String input: alphabet) {
				String output = tmpModel.getOutput(state, input);
				Integer successor = tmpModel.getSuccessor(state, input);
				psAutFile.println("(" + state + ",'" + input + " / " + output + "', " + successor + ")");
			}
		}
		
		psAutFile.close();
	}
	
	public static void writeDotModel(MealyMachine<?, String, ?, String> model, SimpleAlphabet<String> alphabet, String filename) throws IOException, InterruptedException {
		// Write output to dot-file
		File dotFile = new File(filename);
		PrintStream psDotFile = new PrintStream(dotFile);
		GraphDOT.write(model, alphabet, psDotFile);
		psDotFile.close();
		
		//TODO Check if dot is available
		
		// Convert .dot to .pdf
		Runtime.getRuntime().exec("dot -Tpdf -O " + filename);
	}
	
	public void configureLogging(String output_dir) throws SecurityException, IOException {
		LearnLogger loggerLearnlib = LearnLogger.getLogger("de.learnlib");
		loggerLearnlib.setLevel(Level.ALL);
		FileHandler fhLearnlibLog = new FileHandler(output_dir + "/learnlib.log");
		loggerLearnlib.addHandler(fhLearnlibLog);
		fhLearnlibLog.setFormatter(new SimpleFormatter());
		
		LearnLogger loggerLearner = LearnLogger.getLogger(Learner.class.getSimpleName());
		loggerLearner.setLevel(Level.ALL);
		FileHandler fhLearnerLog = new FileHandler(output_dir + "/learner.log");
		loggerLearner.addHandler(fhLearnerLog);
		fhLearnerLog.setFormatter(new SimpleFormatter());
		loggerLearner.addHandler(new ConsoleHandler());
		
		LearnLogger loggerLearningQueries = LearnLogger.getLogger("learning_queries");
		loggerLearningQueries.setLevel(Level.ALL);
		FileHandler fhLearningQueriesLog = new FileHandler(output_dir + "/learning_queries.log");
		loggerLearningQueries.addHandler(fhLearningQueriesLog);
		fhLearningQueriesLog.setFormatter(new SimpleFormatter());
		loggerLearningQueries.addHandler(new ConsoleHandler());		

		LearnLogger loggerEquivalenceQueries = LearnLogger.getLogger("equivalence_queries");
		loggerEquivalenceQueries.setLevel(Level.ALL);
		FileHandler fhEquivalenceQueriesLog = new FileHandler(output_dir + "/equivalence_queries.log");
		loggerEquivalenceQueries.addHandler(fhEquivalenceQueriesLog);
		fhEquivalenceQueriesLog.setFormatter(new SimpleFormatter());
		loggerEquivalenceQueries.addHandler(new ConsoleHandler());	
	}
	
	public static void main(String[] args) throws Exception {
		if(args.length < 1) {
			System.err.println("Invalid number of parameters");
			System.exit(-1);
		}
		
		LearningConfig config = new LearningConfig(args[0]);
	
		Learner learner = new Learner(config);
		learner.learn();
		
		System.exit(0);
	}
}
