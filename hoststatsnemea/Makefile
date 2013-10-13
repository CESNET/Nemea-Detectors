CXX=g++
CC=gcc
#CXXFLAGS=-pthread -g
CXXFLAGS=-pthread -O2
LDFLAGS=-pthread -O2
LDLIBS= -ltrap ../../unirec/unirec.o ../../common/cuckoo_hash_v2/libcuckoo_hash_lock.a

STREAM= obj/stream_version
TIMESLOT= obj/timeslot_version

all: cuckoo_hash obj hoststatserv_stream #hoststatserv

# hoststatserv: $(TIMESLOT)/main/hoststatserv.o $(TIMESLOT)/main/processdata.o $(TIMESLOT)/main/requesthandlers.o $(TIMESLOT)/eventhandler.o $(TIMESLOT)/config.o $(TIMESLOT)/main/profile.o $(TIMESLOT)/main/database.o $(TIMESLOT)/lexan.o $(TIMESLOT)/synan.o $(TIMESLOT)/detectionrules.o #$(TIMESLOT)/sshdetection.o
# 	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS)

hoststatserv_stream: $(STREAM)/main/hoststatserv.o $(STREAM)/main/processdata.o $(STREAM)/eventhandler.o $(STREAM)/config.o $(STREAM)/main/profile.o $(STREAM)/main/subprofiles.o $(STREAM)/detectionrules.o #$(STREAM)/main/requesthandlers.o $(STREAM)/main/database.o $(STREAM)/lexan.o $(STREAM)/synan.o $(STREAM)/sshdetection.o
	$(CXX) $(LDFLAGS) $^ -o $@ $(LDLIBS) -D STREAM_VERSION

obj:
	mkdir -p obj/timeslot_version/main obj/stream_version/main

cuckoo_hash:
	$(MAKE) -C ../../common/cuckoo_hash_v2/

# $(TIMESLOT)/%.o: src/%.cpp src/*.h
# 	$(CXX) -c $(CXXFLAGS) -o $@ $<

$(STREAM)/%.o: src/%.cpp src/*.h
	$(CXX) -c $(CXXFLAGS) -o $@ $< -D STREAM_VERSION

# $(TIMESLOT)/main/%.o: src/timeslot_version/%.cpp src/timeslot_version/*.h
# 	$(CXX) -c $(CXXFLAGS) -o $@ $<

$(STREAM)/main/%.o: src/stream_version/%.cpp src/stream_version/*.h
	$(CXX) -c $(CXXFLAGS) -o $@ $< -D STREAM_VERSION

install: all
	./install.sh

clean:
	$(RM) hoststatserv hoststatserv_stream comphoststats obj/timeslot_version/*.o obj/stream_version/*.o obj/timeslot_version/main/*.o obj/stream_version/main/*.o

