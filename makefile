CC = g++
CFLAGS  = -g -Wall

fw: fw.o inputHandler.o
	$(CC) $(CFLAGS) -o fw fw.o inputHandler.o

fw.o:  fw.cpp
	$(CC) $(CFLAGS) -c fw.cpp

inputHandler.o:  inputHandler.cpp inputHandler.h
	$(CC) $(CFLAGS) -c inputHandler.cpp

clean:
	$(RM) fw *.o *~
