CC = gcc
CFLAGS = -Wall -lpthread

svsocks :
	$(CC) $(CFLAGS) -o svsocks svsocks.c

.PHONY = clean
