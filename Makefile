all:
	g++ client.cpp -o client -lcrypto
	g++ server.cpp -o server -lcrypto
clean:
	rm -rf client server *.pem	
