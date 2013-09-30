CC=gcc #-DNO_BLAS_WRAP
CXX=g++
CFLAGS=-std=c99 -O2 -g
CXXFLAGS=-O2 -g
LDFLAGS=

NEMEAFILES=../../unirec/unirec.o -ltrap -lstdc++

#alglib files
ALSRCPATH=alglib/
ALOBJPATH=alglib/
ALGLIBFILES=$(ALOBJPATH)alglibinternal.o $(ALOBJPATH)alglibmisc.o $(ALOBJPATH)ap.o $(ALOBJPATH)dataanalysis.o $(ALOBJPATH)diffequations.o \
	$(ALOBJPATH)fasttransforms.o $(ALOBJPATH)integration.o $(ALOBJPATH)interpolation.o $(ALOBJPATH)linalg.o $(ALOBJPATH)optimization.o \
	$(ALOBJPATH)solvers.o $(ALOBJPATH)specialfunctions.o $(ALOBJPATH)statistics.o

$(ALOBJPATH)%.o ::  $(ALSRCPATH)%.cpp $(ALSRCPATH)%.h
	$(CXX) -c $(CXXFLAGS) $< -o $@

LDLIBS=$(NEMEAFILES) $(ALGLIBFILES) #-L./CLAPACK-3.2.1/ -llapack -lblas -lf2c -lm
#LDLIBS=../../unirec/unirec.o -ltrap -lstdc++ $(ALGLIBFILES)

MODULES=PCA_basic_detector PCA_basic_data_reader #PCA_basic_RT_data_sender PCA_sketch_detector PCA_test_receiver

# Uses default rules
all: $(ALGLIBFILES) ${MODULES}

PCA_basic_detector.o: PCA_basic_detector.cpp PCA_basic.h $(ALGLIBFILES)
	$(CXX) $(CXXFLAGS) -c -o PCA_basic_detector.o PCA_basic_detector.cpp

PCA_basic_data_reader: PCA_basic_data_reader.o
	$(CXX) $(CXXFLAGS) PCA_basic_data_reader.o $(NEMEAFILES) -o PCA_basic_data_reader

PCA_basic_data_reader.o: PCA_basic_data_reader.cpp PCA_basic_data_reader.h PCA_basic.h
	$(CXX) $(CXXFLAGS) -c -o PCA_basic_data_reader.o PCA_basic_data_reader.cpp

PCA_basic_RT_data_sender: PCA_basic_RT_data_sender.o
	$(CXX) $(CXXFLAGS) PCA_basic_RT_data_sender.o $(NEMEAFILES) -o PCA_basic_RT_data_sender

PCA_basic_RT_data_sender.o: PCA_basic_RT_data_sender.cpp PCA_basic_RT_data_sender.h PCA_basic.h
	$(CXX) $(CXXFLAGS) -c -o PCA_basic_RT_data_sender.o PCA_basic_RT_data_sender.cpp

PCA_sketch_detector.o: PCA_sketch_detector.cpp PCA_sketch.h $(ALGLIBFILES)
	$(CXX) $(CXXFLAGS) -c -o PCA_sketch_detector.o PCA_sketch_detector.cpp

PCA_test_receiver.o: PCA_test_receiver.cpp PCA_sketch.h
	$(CXX) $(CXXFLAGS) -c -o PCA_test_receiver.o PCA_test_receiver.cpp

hash_check: hash_check.o
	$(CXX) $(CXXFLAGS) hash_check.o -o hash_check

hash_check.o: hash_check.cpp PCA_sketch.h
	$(CXX) $(CXXFLAGS) -c -o hash_check.o hash_check.cpp

#PCA_test_receiver:
#	$(CXX) $(LDFAGS) ../../unirec/unirec.o -ltrap -lstdc++ -o PCA_test_receiver.cpp

clean:
	rm -f *.o ${MODULES}

clean-alglib:
	rm -f *.o $(ALGLIBFILES)
