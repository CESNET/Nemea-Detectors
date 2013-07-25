CC=gcc
CXX=g++
CFLAGS=-std=c99 -O2 -g
CXXFLAGS=-O2 -g
LDFLAGS=

#alglib files
ALSRCPATH=alglib/
ALOBJPATH=alglib/
ALGLIBFILES=$(ALOBJPATH)alglibinternal.o $(ALOBJPATH)alglibmisc.o $(ALOBJPATH)ap.o $(ALOBJPATH)dataanalysis.o $(ALOBJPATH)diffequations.o \
	$(ALOBJPATH)fasttransforms.o $(ALOBJPATH)integration.o $(ALOBJPATH)interpolation.o $(ALOBJPATH)linalg.o $(ALOBJPATH)optimization.o \
	$(ALOBJPATH)solvers.o $(ALOBJPATH)specialfunctions.o $(ALOBJPATH)statistics.o

$(ALOBJPATH)%.o ::  $(ALSRCPATH)%.cpp $(ALSRCPATH)%.h
	$(CXX) -c $(CXXFLAGS) $< -o $@
	
LDLIBS=../../unirec/unirec.o $(ALGLIBFILES) -ltrap -lstdc++

MODULES=PCA_sketch_detector #PCA_sketch_identificator

# Uses default rules
all: $(ALGLIBFILES) ${MODULES}

clean:
	rm -f *.o ${MODULES}
