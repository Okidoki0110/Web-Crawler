CC=g++
CFLAGS=-I.

client: client.c json11.cpp		
		$(CC) -std=c++11 -O2 -Wfatal-errors client.c json11.cpp -o client		
run: client
		./client
clean:
		rm -f *.o client
