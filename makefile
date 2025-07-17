CC = gcc
CFLAGS = -I/usr/local/openssl-3.0.15/include -pthread -lrt
LDFLAGS = -L/usr/local/openssl-3.0.15/lib64 -Wl,-rpath=/usr/local/openssl-3.0.15/lib64 -lssl -lcrypto

SERVER_SRC = server.c
CLIENT_SRC = client.c

all: server client

server: $(SERVER_SRC)
	$(CC) $(SERVER_SRC) -o server $(CFLAGS) $(LDFLAGS)

client: $(CLIENT_SRC)
	$(CC) $(CLIENT_SRC) -o client $(CFLAGS) $(LDFLAGS)

clean:
	rm -f server client
