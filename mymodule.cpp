#include "mymodule.h"
#include "../unirec.h"
#include <assert.h>
#include <string>
#include <iostream>

using namespace std;

// Module specification
string ifc_spec_in[] = {UR_NF5::GetSpec()};
string ifc_spec_out[] = {UR_NF5::GetSpec(), UR_NF5::GetSpec()};
const NemeaModuleSpec module_spec = {
   "MyModule",
   "Module description.",
   1,
   2,
   ifc_spec_in,
   ifc_spec_out,
};

/* Return module specification */
NemeaModuleSpec MyModule::GetModuleSpec()
{
   return module_spec;
}

/* Constructor, register receive method */
MyModule::MyModule(InputInterface** ifcin, OutputInterface** ifcout)
 : NemeaModule<1,2>(ifcin, ifcout)
{
   ifcin[0]->RegisterRecvMethod(this, (RecvMethodPtr)&MyModule::RecvRecord);
}

/* Initialization, in this case do nothing */
void MyModule::Init(const string &params)
{
   // do nothing
}

/* Receive method - called every time a record arrives at input */
void MyModule::RecvRecord(const void *record, unsigned int size)
{
   static int i = 0;
   
   // Copy and reinterpret input data
   assert(size >= sizeof(UR_NF5));
   UR_NF5 rec = asUniRec(record, UR_NF5);
   // or:
   //UR_NF5 rec = *reinterpret_cast<const UR_NF5*>(record);
   
   // process record (swap addresses)
   uint32_t tmp = rec.src_ip;
   rec.src_ip = rec.dst_ip;
   rec.dst_ip = tmp;
   
//       cout << i++ << endl;
   
   // put record to both outputs
   ifcout[0]->SendRecord(&rec, sizeof(UR_NF5));
   ifcout[1]->SendRecord(&rec, sizeof(UR_NF5));
}
