tomato: tomato.cpp client.cpp server.cpp bind.cpp ubind.cpp
	g++ tomato.cpp client.cpp server.cpp bind.cpp ubind.cpp -lpthread -lssl -lcrypto -O2 -o tomato
