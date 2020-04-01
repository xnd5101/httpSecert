
CXX = g++
DEBUG = -g -O2
CC_FLAGS = $(DEBUG) 

CC_FLAGS += -I./
CC_FLAGS += -std=c++11
CC_FLAGS += -I./common/include

LIB_PATH += -L./common/lib

LIBS = -lpthread
LIBS = -lcryptopp
#LIB += -Wl,-rpath=./common/lib -lcryptopp -lrt

OBJS = main.o base64.o cryptoppCommon.o

EXEC = server

$(EXEC): $(OBJS)
	$(CXX) $(CC_FLAGS) $(OBJS) -o $@  $(LIB_PATH) $(LIBS)


main.o: main.cpp
	$(CXX) $(CC_FLAGS) -c -o $@ main.cpp

base64.o: base64.cpp base64.h
	$(CXX) $(CC_FLAGS) -c -o $@ base64.cpp 

cryptoppCommon.o: cryptoppCommon.cpp cryptoppCommon.h
	$(CXX) $(CC_FLAGS) -c -o $@ cryptoppCommon.cpp 


all: $(EXEC)
	
.PHONY:clean
clean:
	rm -rf $(OBJS) $(EXEC) 

