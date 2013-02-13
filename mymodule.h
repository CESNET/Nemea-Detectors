#ifndef _MYMODULE_H_
#define _MYMODULE_H_
//////////////////////////////////////
// Example of module implementation

#include "nemeamodule.h"
#include "../ifcbase.h"
#include <string>

#define MODULE MyModule

class MyModule : public NemeaModule<1,2> {
public:
   /* Return module specification */
   static NemeaModuleSpec GetModuleSpec();
   
   /* Constructor, register receive method */
   MyModule(InputInterface** ifcin, OutputInterface** ifcout);
   
   /* Initialization, in this case does nothing */
   void Init(const std::string &params);
   
   /* Receive method - called every time a record arrives at input */
   void RecvRecord(const void *record, unsigned int size);
};

#endif
