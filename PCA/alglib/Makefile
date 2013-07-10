CXXFLAGS=-O2 -g

.PHONY: all clean

#alglib files
ALSRCPATH=./
ALOBJPATH=./
ALGLIBFILES=$(ALOBJPATH)alglibinternal.o $(ALOBJPATH)alglibmisc.o $(ALOBJPATH)ap.o $(ALOBJPATH)dataanalysis.o $(ALOBJPATH)diffequations.o \
	$(ALOBJPATH)fasttransforms.o $(ALOBJPATH)integration.o $(ALOBJPATH)interpolation.o $(ALOBJPATH)linalg.o $(ALOBJPATH)optimization.o \
	$(ALOBJPATH)solvers.o $(ALOBJPATH)specialfunctions.o $(ALOBJPATH)statistics.o

$(ALOBJPATH)%.o ::  $(ALSRCPATH)%.cpp $(ALSRCPATH)%.h
	g++ -c $(CXXFLAGS) $< -o $@
	
all: $(ALGLIBFILES)

clean:
	rm -f $(ALGLIBFILES)