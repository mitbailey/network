CC = gcc
CXX = g++
EDCFLAGS = -I ./ -Wall -std=c11 -Wno-deprecated-declarations $(CFLAGS)
EDCXXFLAGS = -I./ -Wall -std=c++11 -Wno-deprecated-declarations $(CXXFLAGS)
EDLDFLAGS = -lpthread -lm -lssl -lcrypto $(LDFLAGS)

CXXOBJS = network.o

all: $(CXXOBJS)
	ar -crus libnetwork.a network.o

%.o: %.cpp
	$(CXX) $(EDCXXFLAGS) -o $@ -c $<

.PHONY: clean

clean:
	rm -vf *.out
	rm -vf *.o
	rm -vf *.a