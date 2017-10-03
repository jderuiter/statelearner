# StateLearner

StateLearner is a tool that can learn state machines from implementations using a black-box approach. It makes use of LearnLib for the learning specific algorithms.

This tool can be used for TLS implementations, smart cards and can be extended using its socket module. 

An overview of different security protocols where state machine learning has been applied can be found [here](http://www.cs.ru.nl/~joeri/StateMachineInference.html).

## Requirements

* graphviz

## Build

Build a self-contained jar file using the following command:

`mvn package shade:shade`

## Usage

`java -jar stateLearner-0.0.1-SNAPSHOT.jar <configuration file>`

Example configurations can be found in the 'examples' directory. To run the OpenSSL example:

```
cd examples/openssl
java -jar ../../target/stateLearner-0.0.1-SNAPSHOT.jar server.properties
```

## Publications

StateLearner (or one of its predecessors) has been used in the following publications:
* [Automated Reverse Engineering using Lego](https://www.usenix.org/conference/woot14/workshop-program/presentation/chalupar), Georg Chalupar, Stefan Peherstorfer, Erik Poll and Joeri de Ruiter
* [Protocol state fuzzing of TLS implementations](https://www.usenix.org/conference/usenixsecurity15/technical-sessions/presentation/de-ruiter), Joeri de Ruiter and Erik Poll
* [A Tale of the OpenSSL State Machine: a Large-scale Black-box Analysis](http://www.cs.ru.nl/~joeri/papers/nordsec16.pdf), Joeri de Ruiter
