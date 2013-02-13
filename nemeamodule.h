#ifndef _NEMEAMODULE_H_
#define _NEMEAMODULE_H_

#include <string>

//#include "ifcbase.h"
class InputInterface;
class OutputInterface;

/////////////////////////////////////////////
// Module specification
struct NemeaModuleSpec {
   std::string name;
   std::string description;
   int num_ifc_in;
   int num_ifc_out;
   std::string *ifc_spec_in; // specifikuje datový typ rozhraní nebo "Universal", pokud je mu to jedno (napø. copy, multiplex apod.)
   std::string *ifc_spec_out;
};



class NemeaModuleBase {
   // Nothing here
   // It's just a non-template base class, so ifcbase.h can define 
   // pointer to NemeaModule's method without knowledge of template parameters.
};

/////////////////////////////////////////////
// Module base class
template<unsigned INPUTS, unsigned OUTPUTS>
class NemeaModule : public NemeaModuleBase {
protected:
   InputInterface *ifcin[INPUTS];
   OutputInterface *ifcout[OUTPUTS];

   /* Constructor, store pointers to interface instances. */
   NemeaModule(InputInterface** ifcin, OutputInterface** ifcout)
   {
      // Copy pointers to interfaces
      for (int i = 0; i < INPUTS; i++)
         this->ifcin[i] = ifcin[i];
      for (int i = 0; i < OUTPUTS; i++)
         this->ifcout[i] = ifcout[i];
   }

public:
   /* Return information about module, its interfaces and their UniRec templates. */
   static NemeaModuleSpec GetModuleSpec();
   
   /* Module-specific initialization, can receive any parameters as a string. */
   virtual void Init(const std::string &params) {};
};

#endif
