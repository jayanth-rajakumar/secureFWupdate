all:
	g++ -O0 -g  client.cpp -o client -Wall -lcrypto -lssl
	g++ -O0 -g server.cpp -o server -Wall -lcrypto -lssl
	truncate -s 32M fw.bin
clean:
	rm -rf client server *.pem nonces.txt fw.bin TH_fw.bin	
