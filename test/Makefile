CC=gcc
CFLAGS=-Wall
LDFLAGS=-pthread
TARGET_SERVER=udp_server
TARGET_CLIENT=udp_client

all: $(TARGET_SERVER) $(TARGET_CLIENT)

$(TARGET_SERVER): udp_server.c
	$(CC) $(CFLAGS) -o $(TARGET_SERVER) udp_server.c $(LDFLAGS)

$(TARGET_CLIENT): udp_client.c
	$(CC) $(CFLAGS) -o $(TARGET_CLIENT) udp_client.c $(LDFLAGS)

clean:
	rm -f $(TARGET_SERVER) $(TARGET_CLIENT)

.PHONY: all clean
