CXX=g++
CC=gcc
#CXXFLAGS=-pthread -g
CXXFLAGS=-pthread -O2
LDFLAGS=-pthread -O2
LDLIBS= -ltrap ../../unirec/unirec.o ../../common/cuckoo_hash_v2/libcuckoo_hash_lock.a


all: cuckoo_hash obj hoststatsnemea

hoststatsnemea: obj/hoststatserv.o obj/processdata.o obj/eventhandler.o obj/config.o obj/profile.o obj/subprofiles.o obj/detectionrules.o #obj/requesthandlers.o obj/database.o obj/lexan.o obj/synan.o obj/sshdetection.o
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

obj:
	mkdir -p obj

cuckoo_hash:
	$(MAKE) -C ../../common/cuckoo_hash_v2/

obj/%.o: src/%.cpp src/*.h
	$(CXX) -c $(CXXFLAGS) -o $@ $<

clean:
	$(RM) hoststatsnemea obj/*.o

