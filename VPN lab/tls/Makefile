all: 
	gcc -o tlsclient tlsclient.c -lssl -lcrypto -lpthread
	gcc -o tlsserver tlsserver.c -lssl -lcrypto -lpthread -lcrypt

clean: 
	rm tlsclient tlsserver 

