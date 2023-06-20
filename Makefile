CC = gcc
CFLAGS = -Wall -Wextra
LDFLAGS = -lssl -lcrypto
MBEDTLS_FLAGS = -lmbedtls -lmbedcrypto -lmbedx509
all:zop zmb
zop: zop.c
	$(CC) $(CFLAGS) $< -o $@ $(LDFLAGS)
zmb: zmb.c
	$(CC) $(CFLAGS) $< -o $@ $(MBEDTLS_FLAGS)

.PHONY: clean
clean:
	rm -f zop zmb
