all:
	g++ -O0 -g  client.cpp -o client -lcrypto
	g++ -O0 -g server.cpp -o server -lcrypto
clean:
	rm -rf client server *.pem	
