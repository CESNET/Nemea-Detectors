/**
 * \file brute_force_detector.h
 * \author Vaclav Pacholik <xpacho03@stud.fit.vutbr.cz || vaclavpacholik@gmail.com>
 * \date 2014
 */

/*
 * Copyright (C) 2014 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */

#include <stdio.h>
#include <iostream>
#include <string.h>
#include <time.h>
#include <inttypes.h>
#include <errno.h>
#include <libxml/parser.h>
#include <unistd.h>
#include <libtrap/trap.h>
#include <map>
#include <algorithm>
#include <typeinfo>
#include <stddef.h>

using namespace std;

const static int USERXML = 1;
const static int PATTERNXML = 2;

typedef enum {
    UINT8_T,
    UINT16_T,
    UINT32_T,
    UINT64_T,
    FLOAT,
    DOUBLE,
    STRING,
    STRUCT
} varType;

typedef enum {
    VARIABLE,
    USTRUCT
} userType;

typedef struct {
    string name;
	varType type;
    void *defaultValue;
    string defaultStringValue;
	void *map;
    bool isRequired;
    int offset;
    int stringMaxSize;
} configStrucItem;

typedef struct {
    userType type;
    string name;
    string value;
    void *map;
} userConfigItem;

typedef struct {
    string patternModuleName;
    string patternModuleAuthor;
    string userModuleName;
    string userModuleAuthor;
    //TODO: other stuff
} infoStruct;

typedef struct __attribute__ ((__packed__)) {
    uint8_t Variable1;//0
    double Variable2;//1
    uint32_t Variable_optional;//9
    char Variable_string[8];//13
    struct __attribute__ ((__packed__)){
        uint8_t Struct_variable1;//21
        uint32_t Struct_optional_variable;//22
    }first_struct;
    char Last_param[10];//26
}userStructure;

map<string, configStrucItem> *configStructureMap;
map<string, userConfigItem> *userConfigMap;
infoStruct moduleInfo; 
int globalStructureOffset = 0;

xmlDocPtr doc;
xmlDocPtr userDoc;


void clearConfigStructureMap(map<string, configStrucItem> *configMap)
{
    map<string, configStrucItem>::iterator it = configMap->begin();

    while (it != configMap->end()) {
        if (it->second.map != NULL) {
            clearConfigStructureMap((map<string, configStrucItem> *)it->second.map);
        }

        if (it->second.defaultValue != NULL) {
            free(it->second.defaultValue);
        }
      
        it++;
    }
    configMap->clear();
    delete (map<string, configStrucItem>*)configMap;
}

void clearConfigStructureMap(map<string, userConfigItem> *configMap)
{
    map<string, userConfigItem>::iterator it = configMap->begin();

    while (it != configMap->end()) {
        if (it->second.map != NULL) {
            clearConfigStructureMap((map<string, userConfigItem> *)it->second.map);
        }
        it++;
    }
    configMap->clear();
    delete (map<string, userConfigItem>*)configMap;
}

void printTypeAndDefaultValue(configStrucItem item) {

    switch(item.type) {
        case UINT8_T:
            cout << "UINT8_T" << endl;
            cout << "DefaultValue: " << *(uint8_t*)item.defaultValue << endl;
            break;
        case UINT16_T:
            cout << "UINT16_T" << endl;
            cout << "DefaultValue: " << *(uint16_t*)item.defaultValue << endl;
            break;
        case UINT32_T:
            cout << "UINT32_T" << endl;
            cout << "DefaultValue: " << *(uint32_t*)item.defaultValue << endl;
            break;
        case UINT64_T:
            cout << "UINT64_T" << endl;
            cout << "DefaultValue: " << *(uint64_t*)item.defaultValue << endl;
            break;
        case FLOAT:
            cout << "FLOAT" << endl;
            cout << "DefaultValue: " << *(float*)item.defaultValue << endl;
            break;
        case DOUBLE:
            cout << "DOUBLE" << endl;
            cout << "DefaultValue: " << *(double*)item.defaultValue << endl;
            break;
        case STRING:
            cout << "STRING" << endl;
            cout << "DefaultValue: " << item.defaultStringValue.c_str() << endl;
            break;
        default:
            break;
    }
}

void printConfigMap(map<string, configStrucItem> *configMap)
{
    map<string, configStrucItem>::iterator it = configMap->begin();
        
    while(it != configMap->end())
    {
        cout << "Element name: " << it->second.name << endl;
        if (it->second.isRequired) {
            cout << "Element is required." << endl;
        } else {
            cout << "Element is optional." << endl;
        }

        if (it->second.type == STRUCT) {
            cout << "--------------------------" << endl;
            printConfigMap(((map<string, configStrucItem> *)it->second.map));
            cout << "--------------------------" << endl;
        } else {
            cout << "Element type: "; printTypeAndDefaultValue(it->second);
            cout << "****************" << endl;
        }
        it++;
    }
}

void printUserMap(map<string, userConfigItem> *configMap)
{
    map<string, userConfigItem>::iterator it = configMap->begin();

    while(it != configMap->end()) {
        
        if (it->second.type == USTRUCT) {
            cout << "Struct name: " << it->second.name << endl;
            printUserMap((map<string, userConfigItem>*)it->second.map);
        } else {
            cout << "Variable name: " << it->second.name << endl;
            cout << "Variable value: " << it->second.value << endl;
        }
        it++;
    }
}

void setType(configStrucItem *item, string type)
{
    if (type.compare("uint8_t") == 0) {
        item->type = UINT8_T;
    } else if (type.compare("uint16_t") == 0) {
        item->type = UINT16_T;
    } else if (type.compare("uint32_t") == 0) {
        item->type = UINT32_T;
    } else if (type.compare("uint64_t") == 0) {
        item->type = UINT64_T;
    } else if (type.compare("float") == 0) {
        item->type = FLOAT;
    } else if (type.compare("double") == 0) {
        item->type = DOUBLE;
    } else if (type.compare("string") == 0) {
        item->type = STRING;
    }
}

void addElement(string name, string type, string defValue, string charArraySize, bool requiredFlag, map<string, configStrucItem> *structMap)
{
	configStrucItem tmpItem;
        
    tmpItem.name = name;
    tmpItem.map = NULL;
    tmpItem.defaultValue = NULL;
    setType(&tmpItem, type);

    tmpItem.isRequired = requiredFlag;

    tmpItem.offset = globalStructureOffset;

    switch(tmpItem.type) {
        case UINT8_T:
            tmpItem.defaultValue = malloc(sizeof(uint8_t*));
            *(uint8_t*)tmpItem.defaultValue = (uint8_t)atoi(defValue.c_str());
            globalStructureOffset += sizeof(uint8_t);
            break;
        case UINT16_T:
            tmpItem.defaultValue = malloc(sizeof(uint16_t*));
            *(uint16_t*)tmpItem.defaultValue = (uint16_t)atoi(defValue.c_str());
            globalStructureOffset += sizeof(uint16_t);
            break;
        case UINT32_T:
            tmpItem.defaultValue = malloc(sizeof(uint32_t*));
            *(uint32_t*)tmpItem.defaultValue = (uint32_t)atoi(defValue.c_str());
            globalStructureOffset += sizeof(uint32_t);
            break;
        case UINT64_T:
            tmpItem.defaultValue = malloc(sizeof(uint64_t*));
            *(uint64_t*)tmpItem.defaultValue = (uint64_t)atoi(defValue.c_str());
            globalStructureOffset += sizeof(uint64_t);
            break;
        case FLOAT:
            tmpItem.defaultValue = malloc(sizeof(float*));
            *(float*)tmpItem.defaultValue = (float)atof(defValue.c_str());
            globalStructureOffset += sizeof(float);
            break;
        case DOUBLE:
            tmpItem.defaultValue = malloc(sizeof(double*));
            *(double*)tmpItem.defaultValue = (double)atof(defValue.c_str());
            globalStructureOffset += sizeof(double);
            break;
        case STRING:
            tmpItem.defaultStringValue = defValue;
            globalStructureOffset += atoi(charArraySize.c_str());
            tmpItem.stringMaxSize = atoi(charArraySize.c_str()) +1;
            break;
        default:
            break;
    }


    if (structMap == NULL)
        configStructureMap->insert(pair<string, configStrucItem>(tmpItem.name, tmpItem));
    else 
        structMap->insert(pair<string, configStrucItem>(tmpItem.name, tmpItem));
}

bool parseStruct(xmlNodePtr parentNode, map<string, configStrucItem> *structMap)
{
	xmlNodePtr structNode = parentNode->xmlChildrenNode;
   	xmlAttrPtr structXmlAttr = parentNode->properties;
   	xmlChar * tmpXmlChar;

    while (structXmlAttr != NULL) {
    	xmlChar * structXmlChar = xmlGetProp(parentNode, structXmlAttr->name);
		xmlFree(structXmlChar);
		structXmlAttr = structXmlAttr->next;
    }  

    while (structNode != NULL) {	
    	if(xmlStrcmp(structNode->name, (const xmlChar *) "element") == 0) {
    		xmlAttrPtr tmpXmlAttr = structNode->properties;
    		bool requiredFlag = false;

    		while (tmpXmlAttr != NULL) {
    			xmlChar * attXmlChar = xmlGetProp(structNode, tmpXmlAttr->name);
                if(xmlStrcmp(attXmlChar, (const xmlChar *) "required") == 0) {
                    requiredFlag = true;
                }
				xmlFree(attXmlChar);
    			tmpXmlAttr = tmpXmlAttr->next;
    		}  

    		xmlNodePtr elementContent = structNode->xmlChildrenNode;

    		string elementName;
    		string elementType;
    		string elementDefValue;
            string charArraySize;

    		while(elementContent != NULL) {
    			if(xmlStrcmp(elementContent->name, (const xmlChar *) "name") == 0) {
    				tmpXmlChar = xmlNodeGetContent(elementContent);
    				elementName.assign((const char *)tmpXmlChar);
    				xmlFree(tmpXmlChar);
    			} else if (xmlStrcmp(elementContent->name, (const xmlChar *) "type") == 0) {
    				tmpXmlChar = xmlNodeGetContent(elementContent);
                    if (xmlStrcmp(tmpXmlChar, (const xmlChar *) "string") == 0) {
                        xmlAttrPtr stringAttr = elementContent->properties;

                        while (stringAttr != NULL) {
                            xmlChar *stringAttChar = xmlGetProp(elementContent, stringAttr->name);
                            charArraySize.assign((const char *)stringAttChar);
                            xmlFree(stringAttChar);
                            stringAttr = stringAttr->next;
                        }
                    }
    				elementType.assign((const char *)tmpXmlChar);
    				xmlFree(tmpXmlChar);
    			} else if (xmlStrcmp(elementContent->name, (const xmlChar *) "default-value") == 0) {
    				tmpXmlChar = xmlNodeGetContent(elementContent);
    				elementDefValue.assign((const char *)tmpXmlChar);
    				xmlFree(tmpXmlChar);
    			}

    			elementContent = elementContent->next;
    		}
    		addElement(elementName, elementType, elementDefValue, charArraySize, requiredFlag, structMap);

	   	} else if (xmlStrcmp(structNode->name, (const xmlChar *) "struct") == 0) {
            configStrucItem tmpItem;
            string structureName;
            xmlAttrPtr structXmlAttr2 = parentNode->properties;

            while (structXmlAttr2 != NULL) {
                xmlChar * attXmlStructChar = xmlGetProp(structNode, structXmlAttr2->name);
                structureName.assign((const char *)attXmlStructChar); 
                xmlFree(attXmlStructChar);
                structXmlAttr2 = structXmlAttr2->next;
            }  

            tmpItem.type = STRUCT;
            tmpItem.name = structureName;
            tmpItem.defaultValue = NULL;
            map<string, configStrucItem> *newStructMap = new map<string, configStrucItem>;
            if (newStructMap == NULL)
            {
                cerr << "parser error, cannot allocate enought space for sub-map." << endl;
                return false;
            }
            tmpItem.map = (void*)newStructMap;

            if (structMap == NULL) 
                configStructureMap->insert(pair<string, configStrucItem>(tmpItem.name, tmpItem));
            else
                structMap->insert(pair<string, configStrucItem>(tmpItem.name, tmpItem));

    		parseStruct(structNode, newStructMap);
    	}	 

    	structNode = structNode->next;
    }  		
    xmlFree(structNode);

	return true;
}

void addElementToUserMap(string name, string value, map<string, userConfigItem> *userMap)
{
    userConfigItem tmpItem;
    tmpItem.name = name;
    tmpItem.value = value;
    tmpItem.type = VARIABLE;
    tmpItem.map = NULL;

    if (userMap == NULL)
        userConfigMap->insert(pair<string, userConfigItem>(tmpItem.name, tmpItem));
    else 
        userMap->insert(pair<string, userConfigItem>(tmpItem.name, tmpItem));
}

bool parseUserStruct(xmlNodePtr parentNode, map<string, userConfigItem> *structMap)
{
    xmlNodePtr structNode = parentNode->xmlChildrenNode;
    xmlChar * tmpXmlChar;

    while (structNode != NULL) {    
        if(xmlStrcmp(structNode->name, (const xmlChar *) "element") == 0) {
            xmlAttrPtr tmpXmlAttr = structNode->properties;
            string variableName;
            string variableValue;

            while (tmpXmlAttr != NULL) {
                xmlChar * attXmlChar = xmlGetProp(structNode, tmpXmlAttr->name);
                variableName.assign((const char *)attXmlChar);
                xmlFree(attXmlChar);
                tmpXmlAttr = tmpXmlAttr->next;
            }  
            tmpXmlChar = xmlNodeGetContent(structNode);
            variableValue.assign((const char *)tmpXmlChar);
            variableValue.erase(std::remove(variableValue.begin(), variableValue.end(), '\t'), variableValue.end());
            variableValue.erase(std::remove(variableValue.begin(), variableValue.end(), '\n'), variableValue.end());
            xmlFree(tmpXmlChar);

            addElementToUserMap(variableName, variableValue, structMap);

        } else if (xmlStrcmp(structNode->name, (const xmlChar *) "struct") == 0) {
            xmlAttrPtr structXmlAttr = structNode->properties;
            string structName;

            while (structXmlAttr != NULL) {
                xmlChar * attXmlChar = xmlGetProp(structNode, structXmlAttr->name);
                structName.assign((const char *) attXmlChar);
                xmlFree(attXmlChar);
                structXmlAttr = structXmlAttr->next;
            }  

            userConfigItem tmpItem;
            tmpItem.name = structName;
            tmpItem.type = USTRUCT;
            
            map<string, userConfigItem> *userStructSubMap = new map<string, userConfigItem>;
            if (userStructSubMap == NULL) {
                cerr << "parser error, cannot allocate enought space for sub-map." << endl;
                return false;
            }

            tmpItem.map = (void*)userStructSubMap;

            if (structMap == NULL) {
                userConfigMap->insert(pair<string, userConfigItem>(tmpItem.name, tmpItem));
            } else {
                structMap->insert(pair<string, userConfigItem>(tmpItem.name, tmpItem));
            }

            parseUserStruct(structNode, userStructSubMap);
        }

        structNode = structNode->next;
    }
    xmlFree(structNode);

    return true;
}

bool checkHeader(xmlNodePtr cur)
{
    if (cur == NULL) {
        cerr << "parser error, input user configuration is empty." << endl;
        return false;
    }

    if (xmlStrcmp(cur->name, (const xmlChar *) "configuration")) {
        cerr << "parser error, root element is not valid, <" << cur->name <<"> found, must be <configuration>." << endl;
        return false;
    }

    return true;
}

bool parseStruct(xmlDocPtr *doc, int typeOfParsing)
{
    xmlNodePtr cur;
    xmlChar *tmpXmlChar;
    bool retValue = false;

    cur = xmlDocGetRootElement(*doc);
    bool isHeaderOk = checkHeader(cur);
    if (!isHeaderOk)
        return false;

    cur = cur->xmlChildrenNode;
    while (cur != NULL) {
        if (xmlStrcmp(cur->name, (const xmlChar *) "module-name") == 0) {
            tmpXmlChar = xmlNodeGetContent(cur);
            moduleInfo.patternModuleName.assign((const char *)tmpXmlChar);
            cout << "Module name: " << tmpXmlChar << endl;
            xmlFree(tmpXmlChar);
        }

        if (xmlStrcmp(cur->name, (const xmlChar *) "module-author") == 0) {
            tmpXmlChar = xmlNodeGetContent(cur);
            moduleInfo.patternModuleAuthor.assign((const char *)tmpXmlChar);
            cout << "Module author: " << tmpXmlChar << endl;
            xmlFree(tmpXmlChar);
        }
        
        if (xmlStrcmp(cur->name, (const xmlChar *) "struct") == 0) {
            if (typeOfParsing == PATTERNXML) {
                retValue = parseStruct(cur,NULL);
            } else {
                retValue = parseUserStruct(cur,NULL);
            }
            
            if (!retValue){
                break;
            }
        }
        cur = cur->next;
    }

    return true;
}

void setUserValueToConfig(configStrucItem *configStruct, userConfigItem *userStruct)
{   
    switch(configStruct->type) {
        case UINT8_T:
            *(uint8_t*)configStruct->defaultValue = (uint8_t)atoi(userStruct->value.c_str());
            break;
        case UINT16_T:
            *(uint16_t*)configStruct->defaultValue = (uint16_t)atoi(userStruct->value.c_str());
            break;
        case UINT32_T:
            *(uint32_t*)configStruct->defaultValue = (uint32_t)atoi(userStruct->value.c_str());
            break;
        case UINT64_T:
            *(uint64_t*)configStruct->defaultValue = (uint64_t)atoi(userStruct->value.c_str());
            break;
        case FLOAT:
            *(float*)configStruct->defaultValue = (float)atof(userStruct->value.c_str());
            break;
        case DOUBLE:
            *(double*)configStruct->defaultValue = (double)atof(userStruct->value.c_str());
            break;
        case STRING:
            configStruct->defaultStringValue = userStruct->value;
        default:
            break;
    }
}

bool fillConfigStruct(map<string, configStrucItem> *patternMap, map<string, userConfigItem> *userMap)
{
    map<string, configStrucItem>::iterator it = patternMap->begin();

    while (it != patternMap->end()) {
        map<string, userConfigItem>::iterator userMapIt = userMap->find(it->first);
        if (userMapIt == userMap->end()) {
            if (it->second.isRequired) {
                cerr << "validation failed, variable (" << it->second.name << ") is required, but not found in user configuration file." << endl;
                return false;
            } else {
                it++;
                continue;
            }
        } 

        if (userMapIt->second.type == USTRUCT) {
            bool retVal = fillConfigStruct((map<string, configStrucItem>*)it->second.map, (map<string, userConfigItem>*)userMapIt->second.map);
            if (!retVal) {
                return false;
            }
        }
        setUserValueToConfig(&it->second, &userMapIt->second);
        it++;
    }
    return true;
}

void getConfiguration(userStructure *inputStruct, map<string, configStrucItem> *configureMap)
{
    map<string, configStrucItem>::iterator it = configureMap->begin();

    char *base_addres = (char*)inputStruct; 

    while (it != configureMap->end()) {
        switch(it->second.type) {
            case UINT8_T:
                *(uint8_t*)((char*)inputStruct + it->second.offset) = *((uint8_t*)(it->second).defaultValue); 
                break;
            case UINT16_T:
                *(uint16_t*)((char*)inputStruct + it->second.offset) = *((uint16_t*)(it->second).defaultValue); 
                break;
            case UINT32_T:
                *(uint32_t*)((char*)inputStruct + it->second.offset) = *((uint32_t*)(it->second).defaultValue);
                break;
            case UINT64_T:
                *(uint64_t*)((char*)inputStruct + it->second.offset) = *((uint64_t*)(it->second).defaultValue); 
                break;
            case FLOAT:
                *(float*)((char*)inputStruct + it->second.offset) = *((float*)(it->second).defaultValue);   
                break;
            case DOUBLE:
                *(double*)((char*)inputStruct + it->second.offset) = *((double*)(it->second).defaultValue);     
                break;
            case STRING:
                memcpy(((char*)inputStruct + it->second.offset), (it->second).defaultStringValue.c_str(), (it->second).stringMaxSize);
                break;
            case STRUCT:
                getConfiguration(inputStruct, (map<string, configStrucItem>*)(it->second).map);
                break;
            default:
                break;
        } 
        it++;
    }
}

bool initXmlParser()
{
    configStructureMap  = new map<string, configStrucItem>;
    userConfigMap = new map<string, userConfigItem>;

    if (configStructureMap == NULL) {
        cerr << "parser error, cannot allocate enought space for configuration Map." << endl;
        xmlCleanupParser();
        return EXIT_FAILURE;
    }

    if (userConfigMap == NULL) {
        cerr << "parser error, cannot allocate enought space for User Configuration Map." << endl;
        delete configStructureMap;
        xmlCleanupParser();
        return EXIT_FAILURE;
    }

    return 0;
}

int main(int argc, char** argv)
{
	string structurePatternFile = argv[1];
    string structureUserConfigFile = argv[2];

    initXmlParser();
    
    doc = xmlParseFile(structurePatternFile.c_str());
    if (doc == NULL) {
    	cerr << "parser error, cannot parse configuration file." << endl;
    	return EXIT_FAILURE;
    }

    cout << "Started parsing pattern structure..." << endl;
    bool patternRetVal = parseStruct(&doc, PATTERNXML);

    if (!patternRetVal) {
        cout << "Parsing failed..." << endl;
    } else {
        cout << "Parsing compete..." << endl;  
        //printConfigMap(configStructureMap);   
    }

    userDoc = xmlParseFile(structureUserConfigFile.c_str());
    if (userDoc == NULL) {
        cerr << "parser error, cannot parse user configuration file." << endl;
        return EXIT_FAILURE;
    }

    cout << "Started parsing user config structure..." << endl;
    bool userRetVal = parseStruct(&userDoc, USERXML);
    if (!userRetVal) {
        cout << "Parsing failed..." << endl;
    } else {
        cout << "Parsing complete..." << endl;
        //printUserMap(userConfigMap);
    }

    cout << "Starting validation..." << endl;
    bool validationRetVal = fillConfigStruct(configStructureMap, userConfigMap);
    if (validationRetVal) {
        cout << "Validation complete..." << endl;
        //printConfigMap(configStructureMap);   
    }


    userStructure inputStruct;

    getConfiguration(&inputStruct,configStructureMap);

    cout << "Variable1: ";
    printf("%d\n", (uint8_t)inputStruct.Variable1);

    cout << "Variable2: ";
    printf("%f\n", (double)inputStruct.Variable2);

    cout << "Variable_optional: ";  
    printf("%d\n", (uint32_t)inputStruct.Variable_optional);

    cout << "Variable_string: ";
    string variable_str(inputStruct.Variable_string);
    cout << variable_str.c_str() << endl; 

    cout << "first_struct" << endl;
    cout << "Struct_variable1: ";
    printf("%d\n", (uint8_t)inputStruct.first_struct.Struct_variable1);

    cout << "Struct_optional_variable: ";
    printf("%d\n", (uint32_t)inputStruct.first_struct.Struct_optional_variable);

    cout << "First struct end." << endl;
    cout << "Last_param: ";
    string last_p(inputStruct.Last_param);
    cout << last_p << endl;


    xmlFreeDoc(doc);
    xmlFreeDoc(userDoc);
    xmlCleanupParser();
    clearConfigStructureMap(configStructureMap);
    clearConfigStructureMap(userConfigMap);
}
