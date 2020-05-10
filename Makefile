all:
	g++ -O0 -g  client.cpp -o client -Wall -lcrypto -lssl
	g++ -O0 -g server.cpp -o server -Wall -lcrypto -lssl
clean:
	rm -rf client server *.pem	
