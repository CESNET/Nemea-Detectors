CXX=g++
CC=gcc
#CXXFLAGS=-pthread -g
CXXFLAGS=-pthread -O2
LDFLAGS=-pthread
LDLIBS= -ltrap ../../unirec/unirec.o

all: obj hoststatserv #comphoststats

hoststatserv: obj/hoststatserv.o obj/processdata.o obj/requesthandlers.o obj/eventhandler.o obj/config.o obj/profile.o obj/database.o obj/lexan.o obj/synan.o obj/detectionrules.o #obj/sshdetection.o
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

#comphoststats: obj/comphoststats.o obj/processdata.o obj/database.o obj/config.o obj/eventhandler.o obj/detectionrules.o obj/profile.o
#	$(CXX) $(LDFLAGS) $^ ./nfreader.so -o $@ $(LDLIBS)

obj:
	mkdir -p obj

obj/%.o: src/%.cpp src/*.h
	$(CXX) -c $(CXXFLAGS) -o $@ $<

install: all
	./install.sh

clean:
	$(RM) hoststatserv comphoststats obj/*.o

