/**
 * \file PCA_basic_data_reader.cpp
 * \brief Module for data reading and sending to PCA anomaly detector.
 * \author Pavel Krobot <xkrobo01@stud.fit.vutbr.cz>
 * \date 2013
 */
/*
 * Copyright (C) 2013 CESNET
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
#include <signal.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>
#include <algorithm>

#include <libtrap/trap.h>
#include "../../unirec/unirec.h"

#include "PCA_basic.h"
#include "PCA_basic_data_reader.h"

using namespace std;

// Struct with information about module
trap_module_info_t module_info = {
   // Module name
   (char *) "Data reader for PCA anomaly detection module.\n",
   // Module description
   (char *) "  This module reading data from files and sending them as UniRecs.\n"
   ""
   "Interfaces:\n"
   "  Inputs (0):\n"
   "  Outputs (1):\n"
   "    << 1. UniRec (...):\n"
   "        - ... "
               "....\n",
   0, // Number of input interfaces
   1, // Number of output interfaces
};

static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

string send_one_timebin(pca_basic_settings_t &settings, vector <ifstream*>& in_files,
							uint32_t timebin_counter, void *out_rec, ur_template_t* out_tmplt)
{
	int ret;
	ostringstream state;
	uint32_t packets;
	uint64_t timeslot;
	uint64_t flows/*, packets*/, bytes, link_bit_field;
	float ent_sip, ent_dip, ent_sport, ent_dport;

	ofstream timebin_checker ("tb_checker.txt", ios::in | ios::app);

	#ifdef VALDIATION
	ofstream ofs ("READER-check", ios::in | ios::app);
	#endif//VALDIATION

	for (int i = 0; i < settings.link_count; i++){
		link_bit_field = 0;
		link_bit_field |= MASK_BIT(i);
		*in_files[i] >> timeslot >> flows >> packets >> bytes >> ent_sip >> ent_dip >> ent_sport >> ent_dport;

		if(!in_files[i]->good()){
			if(in_files[i]->eof()){
				state << "End of file reached (link " << settings.link_names[i] << ").\n";
				return state.str();
			}else{
				state << "Input file error (link " << settings.link_names[i] << ").\n";
				return state.str();
			}
		}
		#ifdef VALDIATION
		ofs << timebin_counter << "\t" << flows << "\t" << packets << "\t" << bytes << "\t" << ent_sip << "\t" << ent_dip << "\t" << ent_sport << "\t" << ent_dport << "\t";
		#endif//VALDIATION

		ur_set(out_tmplt, out_rec, UR_TIME_FIRST, timeslot);
		ur_set(out_tmplt, out_rec, UR_LINK_BIT_FIELD, link_bit_field);

		if (settings.agreg_unit_field & MASK_BIT(AU_FLOWS)){
			ur_set(out_tmplt, out_rec, UR_FLOWS, flows);
		}else{
			ur_set(out_tmplt, out_rec, UR_FLOWS, 0);
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_PACKETS)){
			ur_set(out_tmplt, out_rec, UR_PACKETS, packets);
		}else{
			ur_set(out_tmplt, out_rec, UR_PACKETS, 0);
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_BYTES)){
			ur_set(out_tmplt, out_rec, UR_BYTES, bytes);
		}else{
			ur_set(out_tmplt, out_rec, UR_BYTES, 0);
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_ESIP)){
			ur_set(out_tmplt, out_rec, UR_ENTROPY_SRCIP, ent_sip);
		}else{
			ur_set(out_tmplt, out_rec, UR_ENTROPY_SRCIP, 0);
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_EDIP)){
			ur_set(out_tmplt, out_rec, UR_ENTROPY_DSTIP, ent_dip);
		}else{
			ur_set(out_tmplt, out_rec, UR_ENTROPY_DSTIP, 0);
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_ESPORT)){
			ur_set(out_tmplt, out_rec, UR_ENTROPY_SRCPORT, ent_sport);
		}else{
			ur_set(out_tmplt, out_rec, UR_ENTROPY_SRCPORT, 0);
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_EDPORT)){
			ur_set(out_tmplt, out_rec, UR_ENTROPY_DSTPORT, ent_dport);
		}else{
			ur_set(out_tmplt, out_rec, UR_ENTROPY_DSTPORT, 0);
		}

//		cout << "Sending timebin No." << timebin_counter << endl;

		// Send record to interface 0
		ret = trap_send_data(0, out_rec, ur_rec_static_size(out_tmplt), TRAP_WAIT);
		if (ret != TRAP_E_OK) {
			if (ret == TRAP_E_TERMINATED) {
				state << "Module was terminated while waiting for new data (e.g. by Ctrl-C)\n.";
			} else {
				// Some error has occured
				state << "Error: trap_send_data() returned %i (%s)\n" << trap_last_error_msg;
			}
			return state.str();
		}
	}
	timebin_checker << timebin_counter << "\t\t\t" << timeslot << endl;
	timebin_checker.close();
	#ifdef VALDIATION
	ofs << endl;
	ofs.close();
	#endif//VALDIATION

//	cout << timebin_counter << endl;

	state << OK_STRING;
	return state.str();
}

int main(int argc, char **argv)
{
   int ret;
   string state_msg;
   trap_ifc_spec_t ifc_spec;

	string path_to_settings = DEFAULT_PATH_TO_SETTINGS;

	ostringstream string_format;
	string contents;
	size_t start_pos = 0, end_pos = 0;

	pca_basic_settings_t settings;
	settings.path_to_settings = DEFAULT_PATH_TO_SETTINGS;
	settings.out_unirec_specifier = (char *)DEFAULT_UNIREC_SPECIFIER;

   string path_to_data = DEFAULT_PATH_TO_DATA;
   string year = DEFAULT_YEAR;
   string month = DEFAULT_MONTH;
   string start_day = DEFAULT_START_DAY;
   string start_time = DEFAULT_START_TIME;
   string filename_separator = DEFAULT_FILENAME_SEPARATOR;

	ostringstream filename;
	ifstream in_file;
	vector <ifstream*> in_files;

	uint32_t timebin_counter = 0;
   uint32_t timebin_cnt_to_send = DEFAULT_TIMEBIN_CNT_TO_SEND;

	ofstream timebin_checker ("tb_checker.txt");
	timebin_checker << endl;
	timebin_checker.close();

	// ***** Parse params *****
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      cerr << "ERROR in parsing of parameters for TRAP: " << trap_last_error_msg << endl;
      return 1;
   }

	// Parse remaining parameters
   char opt;

   while ((opt = getopt(argc, argv, "c:D:y:m:d:t:s:S:")) != -1) {
      switch (opt) {
      	case 'c':
				timebin_cnt_to_send = atoi(optarg);
				break;
      	case 'D':
				path_to_data = optarg;
				break;
			case 'y':
				year = optarg;
				break;
			case 'm':
				month = optarg;
				break;
			case 'd':
				start_day = optarg;
				break;
			case 't':
				start_time = optarg;
				break;
			case 's':
				filename_separator = optarg;
				break;
         case 'S':
            path_to_settings = optarg;
            break;
//         case 'u':
//            in_unirec_specifier = optarg;
//            break;
         default:
            cerr << "Invalid arguments.\n" << flush;
            return 2;
      }
   }
  if (optind > argc) {
      cerr << "Wrong number of parameters.\n Usage: " << argv[0] << " -i trap-ifc-specifier [-u \"UNIREC,FIELDS\"]"
				" [-c count_of_timebins_to_send]"
				" [-D path/to/data/files]"
				" [-y year] [-m month] [-d start_day] [-t start_time] [-s filename_separator]"
				" [-S path/to/setting/file]"<< endl;
      return 2;
   }
   // ***** END OF Parse params *****
	// ***** Prepairing input data files *****
	if (path_to_data.rfind("/") != (path_to_data.length() - 1) ){
		path_to_data.append("/");
	}
	// *** Parse settings file
	in_file.open(settings.path_to_settings.c_str(), ios::in | ios::binary);
	if (!in_file.is_open()){
		cerr << "Unable to open setting file: " << settings.path_to_settings;
		return 3;
	}else{
		in_file.seekg(0, ios::end);
		contents.resize(in_file.tellg());
		in_file.seekg(0, ios::beg);
		in_file.read(&contents[0], contents.size());
		in_file.close();
	}

	// remove comments
	while((start_pos = contents.find(SETTINGS_COMMENTARY_CHARACTER)) != string::npos){
		end_pos = contents.find("\n", start_pos);
		contents.erase(start_pos, end_pos - start_pos);
	}

	// read link count
	if ((start_pos = contents.find(SETTINGS_OPTION[0])) != string::npos){
		end_pos = contents.find("\n", start_pos);
		string_format.str("");
		string_format.clear();
		string_format << SETTINGS_OPTION[0] << "%u";
		sscanf(contents.substr(start_pos, end_pos - start_pos).c_str(),
				 string_format.str().c_str(), &settings.link_count);
	}else{
		cerr << "No link count founded. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[0] << "\")";
		return 4;
	}
	// get link names
	if (settings.link_count){
		if ((start_pos = contents.find(SETTINGS_OPTION[1])) != string::npos){
			start_pos = contents.find("=", start_pos);
			for (int i = 0; i < settings.link_count; i++){
				if ((end_pos = contents.find(",", start_pos + 1)) != string::npos){
					settings.link_names.push_back(contents.substr(++start_pos, --end_pos - start_pos));
					start_pos = end_pos + 1;
				}else{
					cerr << "Bad link names format. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[1] <<"\")";
					return 4;
				}
			}
		}else{
			cerr << "No link name list. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[1] <<"\")";
			return 4;
		}
	}else{
		cerr << "Link count is empty. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[0] <<"\")";
		return 4;
	}
	// get agregation units selection
	settings.agreg_unit_field = 0;
	settings.agreg_unit_per_link = 0;
	if ((start_pos = contents.find(SETTINGS_OPTION[2])) != string::npos){
		end_pos = contents.find("\n", start_pos);
		for (int i = 0; i < DEFAULT_AGREG_UNIT_CNT; i++){
			if (contents.find(AGREG_UNIT_NAME[i]) != string::npos){
				settings.agreg_unit_field |= MASK_BIT(i);
				++settings.agreg_unit_per_link;
			}
		}
	}else{
		settings.agreg_unit_per_link = DEFAULT_AGREG_UNIT_CNT;
		settings.agreg_unit_field |= MASK_BIT(AU_FLOWS);
		settings.agreg_unit_field |= MASK_BIT(AU_PACKETS);
		settings.agreg_unit_field |= MASK_BIT(AU_BYTES);
		settings.agreg_unit_field |= MASK_BIT(AU_EDIP);
		settings.agreg_unit_field |= MASK_BIT(AU_ESIP);
		settings.agreg_unit_field |= MASK_BIT(AU_ESPORT);
		settings.agreg_unit_field |= MASK_BIT(AU_EDPORT);
	}
	// *** END OF Parse settings file

	for (int i = 0; i < settings.link_count; i++){
		string black_hole_for_headers;
		filename.str("");
		filename.clear();
		filename << path_to_data << settings.link_names[i] << filename_separator << month;
		ifstream *ifs = new ifstream(filename.str().c_str());
		if (!ifs->is_open()){
			cerr << "Unable to open input data file: " << filename.str() << endl;
			return 3;
		}else{
			in_files.push_back(ifs);
			getline(*in_files[i],black_hole_for_headers);//ignoring first line - headers
		}
	}
	// ***** END OF prepairing input data files *****
/* SETINGS CHECK
	cout << "Path to settings file: [" << settings.path_to_settings << "]\n";
	cout << "Out UniRec: [" << settings.in_unirec_specifier << "]\n";
	cout << "Used links (" << settings.link_count << "):\n";
	for (int i = 0; i < settings.link_count; i++){
		cout << "\t" << i << ". " << settings.link_names[i] << "\n";
	}
	cout << "Used agregation units per link (" << settings.agreg_unit_per_link << "):\n";
	for (int i = 0; i < DEFAULT_AGREG_UNIT_CNT; i++){
		if (settings.agreg_unit_field & MASK_BIT(i)){
			cout << "\t" << AGREG_UNIT_NAME[i] << "\n";
		}
	}
	return 0;
*/

	// ***** TRAP initialization *****
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      cerr << "ERROR in TRAP initialization: " << trap_last_error_msg << endl;
      return 2;
   }
   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0);
   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);

	ret = trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_AUTOFLUSH_TIMEOUT, (uint64_t) 500000);
   if (ret != TRAP_E_OK){
   	cerr << "Trap interface control (trap_ifcctl) has returned " << ret << "." << endl;
		stop = 1;
   }
   // ***** END OF TRAP initialization *****

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Create UniRec templates & allocate memory for output records *****
   ur_template_t *out_tmplt = ur_create_template(settings.out_unirec_specifier);

   void *out_rec = ur_create(out_tmplt, 0);
   // ***** END OF Create UniRec templates & allocate memory for output records *****



	// ***** Main processing loop *****
	while (!stop) {
		/** TODO starting from frist line >> start from desired timeslot*/
		state_msg = send_one_timebin(settings, in_files, timebin_counter, out_rec, out_tmplt);
		if(state_msg != OK_STRING){
			cerr << state_msg;
			stop = 1;
			break;
		}

		if(++timebin_counter == timebin_cnt_to_send){//if timebin to send limiit is not set, loop is normaly sended by EOF of input file
			stop = 1;
			break;
		}
	}
	// ***** END OF Main processing loop *****
	cout << timebin_counter << " timebins have been readed & sended (timebin 0 - " << timebin_counter - 1 << ")." << endl;
	// ***** Cleanup *****
	for (int i = 0; i < settings.link_count; i++){
		in_files[i]->close();
		delete in_files[i];
	}

   ur_free(out_rec);
   ur_free_template(out_tmplt);

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();
   // ***** END OF Cleanup *****

   return 0;
}
// END OF PCA_basic_data_reader.cpp
