yalp: clean ydaemon yclient
	g++ -o bin/yalp yclient.o ydaemon.o -std=gnu++11 -pthread
ydaemon: src/ydaemon.cpp
	g++ -c -std=gnu++11 -pthread src/ydaemon.cpp
yclient: src/yclient.cpp
	g++ -c src/yclient.cpp
clean:
	rm -f yclient.o ydaemon.o && mkdir -p bin/

