#!/bin/bash

gcc -Wall -std=gnu99 -g -c -o client.o client.c ;

gcc -Wall -std=gnu99 -g -c -o serveur.o serveur.c ;

gcc -Wall -std=gnu99 -g -c -o main.o main.c ;

gcc -Wall -std=gnu99 -g -c -o list.o list.c ;

gcc -Wall -std=gnu99 -g -c -o interface.o interface.c ;

gcc  interface.o list.o client.o serveur.o main.o -o dazibao \
-L/usr/local/opt/openssl@1.1/lib -lssl -lcrypto -pthread;