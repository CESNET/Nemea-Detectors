/* *** Pass through module *** 
 * Pass data coming from any input to all outputs.
 * 
 * Variable number of inputs and outputs, all should use the same data format
 * (however, module itself is oblivious to data format).
 */    

#include "nemeamodule.h"
#include "../ifcbase.h"
#include <string>

template<unsigned INPUTS = 1, unsigned OUTPUTS = 1>
class PassModule : public NemeaModule<INPUTS, OUTPUTS> {
   static std::string ifc_spec_in[INPUTS];
   static std::string ifc_spec_out[OUTPUTS];
   InputInterface *input[INPUTS];
   OutputInterface *output[OUTPUTS];

public:
   /* Constructor, register receive method */
   PassModule(InputInterface** in_ifcs, OutputInterface** out_ifcs);
   
   /* OutputInterface a string specifying all interfaces and their UniRec templates. */
   static NemeaModuleSpec GetModuleSpec();
   
   /* Callback method for recieving data from outputs */
   void Receive(const void *record, unsigned int size);
};


///////////////////////////////////////////////////////////////////////////////
// Method definitions
// This should normally go to pass_module.cpp, but templates in separate cpp 
// file cause linking problems.

using namespace std;

/* Return module specification. */
template<unsigned INPUTS, unsigned OUTPUTS>
NemeaModuleSpec PassModule<INPUTS,OUTPUTS>::GetModuleSpec()
{
   NemeaModuleSpec spec;
   spec.name = "PassModule";
   spec.description = "Pass data coming from any input to all outputs.";
   spec.num_ifc_in = INPUTS;
   spec.num_ifc_out = OUTPUTS;
   for (int i = 0; i < INPUTS - 1; i++) {
      ifc_spec_in[i] = "X";
   }
   for (int i = 0; i < OUTPUTS - 1; i++) {
      ifc_spec_out[i] = "X";
   }
   spec.ifc_spec_in = ifc_spec_in;
   spec.ifc_spec_out = ifc_spec_out;
   return spec;
}

/* Constructor, register receive method */
template<unsigned INPUTS, unsigned OUTPUTS>
PassModule<INPUTS, OUTPUTS>::PassModule(InputInterface** ifcin, OutputInterface** ifcout)
 : NemeaModule<INPUTS,OUTPUTS>(ifcin, ifcout)
{
   for (int i = 0; i < INPUTS; i++) {
      this->ifcin[i]->RegisterRecvMethod(this, (RecvMethodPtr)&PassModule::Receive);
   }
}

/* Receive function; receive data from input and send it to all outputs. */
template<unsigned INPUTS, unsigned OUTPUTS>
void PassModule<INPUTS, OUTPUTS>::Receive(const void* record, unsigned int size)
{
   for (int i = 0; i < OUTPUTS; i++) {
      this->ifcout[i]->SendRecord(record, size);
   }
}

