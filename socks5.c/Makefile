all: socks5s socks5d

socks5s: main.c
	gcc main.c -lpthread -O2 -o socks5s

socks5d: main.c
	gcc -DDAEMON main.c -lpthread -O2 -o socks5d
