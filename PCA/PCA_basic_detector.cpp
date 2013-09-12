/**
 * \file PCA_basic_detector.cpp
 * \brief Module for detection of network anomalies using PCA.
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
#include <math.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
//#include <dirent.h>
#include <algorithm>

#include <libtrap/trap.h>
#include "../../unirec/unirec.h"

#include "PCA_basic.h"

#include "alglib/dataanalysis.h"
#include "alglib/stdafx.h"

using namespace alglib;
using namespace std;

//#define VALIDATION
#ifdef VALIDATION
#define OUTPUT_LIMITER 20
uint16_t output_counter = 0;
   ostringstream filename;
   ofstream ofs;
#endif

// Struct with information about module
trap_module_info_t module_info = {
   // Module name
   (char *) "Module for anomaly detection using PCA.\n",
   // Module description
   (char *) "  This module detecting network anomalies in flow time series.\n"
   ""
   "Interfaces:\n"
   "  Inputs (1):\n"
   "    >> 1. UniRec (...,"
                     "...)\n"
   "        - data values for one timebin (of given agregation)\n\n"
   "  Outputs (1):\n"
   "    << 1. UniRec (...):\n"
   "        - information about time and agregation unit in witch an "
               "anomaly(-ies) occuring.\n",
   1, // Number of input interfaces
   1, // Number of output interfaces
};

static int stop = 0;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
 * \brief Provedure computes standard deviation from vector (1st version).
 *
 * Provedure computes standard deviation from vector in two different ways - two
 * versions (according to: http://www.mathworks.com/help/matlab/ref/std.html).
 * \param[in] vector_ptr Pointer to vector.
 * \param[in] vector_size Size of vector.
 * \return Real (float) value of stadard deviation.
 */
float vector_standard_deviation (float *vector_ptr, unsigned int vector_size)
{
   float sum=0;
//  SINCE VALUES_ARE_MEAN_CENTERED - HAVE_ZERO_MEAN >> Simplier version:
   for (int i = 0; i < vector_size; i++){
      sum += vector_ptr[i] * vector_ptr[i];
   }
//   printf("\tSUM: %f ---------------------------\n", sum);
   return sqrt(sum / vector_size);
}
/**
 * \brief Procedure computes standard deviation from vector (2nd version).
 * \param[in] vector_ptr Pointer to vector.
 * \param[in] vector_size Size of vector.
 * \return Real (float) value of stadard deviation.
 */
float vector_standard_deviation_v2(float *vector_ptr, unsigned int vector_size)
{
   float sum = 0, tmp;
   float mean = 0;

   for (int i = 0; i < vector_size; i++){
      mean += vector_ptr[i];
   }
   mean /= vector_size;

   for (int i = 0; i < vector_size; i++){
      tmp = vector_ptr[i] - mean;
      sum += tmp * tmp;
   }
//   return sqrt(sum / (vector_size));
   return sqrt(sum / (vector_size-1));
}
/**
*/
float mean_value_from_matrix_column (real_2d_array *data_matrix, unsigned int column)
{
   float sum=0;

   for (int i = 0; i < data_matrix->rows(); i++){
      sum += (*data_matrix)(i,column);
   }
   return sum / data_matrix->rows();
}
/**
 */
float vector_standard_deviation_v2(real_2d_array *data_matrix, unsigned int column)
{
   float sum = 0, tmp;
   float mean = 0;

   mean = mean_value_from_matrix_column(data_matrix, column);

   for (int i = 0; i < data_matrix->rows(); i++){
      tmp = (*data_matrix)(i,column) - mean;
      sum += tmp * tmp;
   }
//   return sqrt(sum / (data_matrix->rows()));
   return sqrt(sum / (data_matrix->rows()-1));
}


//################################################
//## Preprocess data - eliminate x% highest and x% lowest
//#		values, compute mean and crop deviations, bigger then parameter
void preprocess_data(real_2d_array *data_matrix, uint32_t actual_timebin)
{
	float mean, delta_threshold;

   for(int i = 0; i < data_matrix->cols(); i++){
      mean = mean_value_from_matrix_column(data_matrix, i);
//      meanP2 = mean_value_from_matrix_column_power2(dataMatrix, i, NORMAL);
//      delta = sqrt(meanP2);
      delta_threshold = vector_standard_deviation_v2(data_matrix, i);
      delta_threshold *= PREPROCESS_DATA_DEV_MULTIPLIER;
      for(int j = 0; j < data_matrix->rows(); j++){
         if((*data_matrix)(j,i) > (mean + delta_threshold)){
            (*data_matrix)(j,i) = mean;

            if(j == actual_timebin){
               //!!!TODO send / notify ???
            }
         }
         else if((*data_matrix)(j,i) < (mean - delta_threshold)){
            (*data_matrix)(j,i) = mean;

            if(j == actual_timebin){
               //!!!TODO send / notify ???
            }
         }
      }
   }
}

// ***************** MATRIX OPERATIONS *****************************************
/**
 * \brief Procedure transforms columns of matrix to have zero mean
 * \param[in] src_matrix_ptr Pointer to matrix which should be normalized.
 * \param[out] dst_matrix_ptr Pointer to structure for result matrix.
 */
void transform_matrix_zero_mean (float **src_matrix_ptr, real_2d_array *dst_matrix_ptr)
{
   float mean;

   for (int i = 0; i < dst_matrix_ptr->cols(); i++){
      mean = 0;
      for (int j = 0; j < dst_matrix_ptr->rows(); j++){
         mean += src_matrix_ptr[j][i];
      }
      mean /= dst_matrix_ptr->rows();
      for (int j = 0; j < dst_matrix_ptr->rows(); j++){
         (*dst_matrix_ptr)(j,i) = src_matrix_ptr[j][i] - mean;
      }
   }
}

/**
 * \brief Procedure transforms submatrix of matrix to have unit energy.
 *
 * Procedure transforms submatrix of "matrix_ptr", defined by column
 * "start_index" and "last_index", to unit energy (last_index is first which
 * IS NOT affected)
 * \param[in,out] matrix_ptr Pointer to matrix which contains submatrix which
 * should be normalized.
 * \param[in] start_index First column of submatrix (column of matrix from
 * matrix_ptr).
 * \param[in] last_index Last column of submatrix (first column which is not
 * affected) (column of matrix from matrix_ptr).
 */
void  transform_submatrix_unit_energy (real_2d_array *matrix_ptr,
                                       int start_index,
                                       int last_index)
{
   float energy_of_submatrix = 0.0;

   for (int i = start_index; i < last_index; i++){
      for (int j = 0; j < matrix_ptr->rows(); j++){
         energy_of_submatrix += (*matrix_ptr)(j,i) * (*matrix_ptr)(j,i);
      }
   }
   energy_of_submatrix /= (matrix_ptr->rows() *  (last_index-start_index));

   for (int i = start_index; i < last_index; i++){
      for (int j = 0; j < matrix_ptr->rows(); j++){
         (*matrix_ptr)(j,i) /= energy_of_submatrix;
      }
   }
}

// ***************
/**
 * \brief Procedure multiplies submatrix of matrix and same submatrix
 * transposed.
 *
 * Procedure multiplies submatrix of "matrix_ptr" defined by first column (index
 *  0) and parameter (column_delimiter) with the same submatrix transposed.
 * \param[in] matrix_ptr Source matrix.
 * \param[in] column_delimiter Specifies size of submatrix (column count).
 * \param[out] result_ptr Pointer to square matrix for result - size is
 *  calculated from matrix dimensions.
 */
void multiply_submatrix_by_transposed_submatrix (real_2d_array *matrix_ptr,
                                                 uint16_t column_delimiter,
                                                 float **result_ptr)
{
   uint16_t x,y;
   float row_sum;

   for (int i = 0; i < (matrix_ptr->rows() * matrix_ptr->rows()); i++){
      row_sum = 0;

      x = i / matrix_ptr->rows();
      y = i % matrix_ptr->rows();

      for (int j = 0; j < column_delimiter; j++){
         row_sum += (*matrix_ptr)(x,j) * (*matrix_ptr)(y,j);
      }

      result_ptr[x][y] = row_sum;
   }
}

/**
 * \brief Procedure multiplies matrix and transposed row of another matrix.
 * Procedure multiplies first matrix and transposed row of second matrix defined
 * by parameter (row_selector).
 * \param[in] A_matrix_ptr Pointer to first square matrix.
 * \param[in] A_matrix_size Size of first matrix.
 * \param[in] B_matrix_ptr Pointer to second matrix, which contains row, which
 * is used as column vector (transposed row).
 * \param[in] row_selector Specifies row of B_matrix_ptr.
 * \param[out] result_ptr Pointer to vector for result - size is calculated from
 *  matrix dimensions.
 */
void multiply_matrix_by_transposed_line (float **A_matrix_ptr,
                                         unsigned int A_matrix_size,
                                         real_2d_array *B_matrix_ptr,
                                         unsigned int row_selector,
                                         float *result_ptr)
{
   uint16_t y;
   float row_sum;

   for (int i = 0; i < A_matrix_size; i++){
      row_sum = 0;

      y = i;

      for (int j = 0; j < A_matrix_size; j++){
         row_sum += A_matrix_ptr[y][j] * (*B_matrix_ptr)(row_selector,j);
      }

      result_ptr[i] = row_sum;
   }
}
/**
 * \brief Procedure computes norm of vector
 * \param[in] vector_ptr Pointer to vector.
 * \param[in] vector_size Size of vector.
 * \return Returns real (float) value.
 */
float norm_of_vector (float *vector_ptr, unsigned int vector_size)
{
   float sum = 0;

   for (int i = 0; i < vector_size; i++){
      sum += vector_ptr[i] * vector_ptr[i];
   }

   return sqrt(sum);
}


/**
 * \brief Procedure which multiplies matrix by vector.
 *
 * Procedure multiplies source matrix by column of second matrix (vector).
 * Return result in third.
 * \param[in] A_matrix_ptr Pointer to first matrix (A).
 * \param[in] B_matrix_ptr Pointer to second matrix (B).
 * \param[in] B_matrix_column Value which specifies column of second matrix (B).
 * \param[out] result Pointer to vector for result - size is calculated from
 *  matrix dimensions.
 */
void multiply_matrix_column_vector (real_2d_array *A_matrix_ptr,
                                    real_2d_array *B_matrix_ptr,
                                    unsigned int B_matrix_column,
                                    float *result)
{
   float row_sum;
//  if (A_matrix_ptr->cols()==B_matrix_ptr->rows()){ //check if matrixes have proper size
   for (int i = 0; i < A_matrix_ptr->rows(); i++){
      row_sum = 0;
      for (int j = 0; j < A_matrix_ptr->cols(); j++){
         row_sum += (*A_matrix_ptr)(i,j) * (*B_matrix_ptr)(j,B_matrix_column);
      }
      result[i] = row_sum;
   }
//  }
}

/**
 * \brief Procedure divides vector by value.
 *
 * Procedure divides vector by value - overwrite original vector.
 * \param[in] vector_ptr Pointer to vector which should by divided.
 * \param[in] vector_size Size of vector which should by divided.
 * \param[in] Real (float) value by which should be vector divided.
 */
void divide_vector_by_value (float *vector_ptr, unsigned int vector_size, float divider)
{
   for (int i = 0; i < vector_size; i++){
      vector_ptr[i] /= divider;
   }
}

/**
 * \brief Procedure substitutes square matrix from identity matrix of same size.
 * Overwrites original matrix.
 * \param[in,out] matrix_ptr Pointer to matrix.
 * \param[in] matrix_size Size of matrix.
 */
void substitute_from_identity_matrix (float **matrix_ptr, unsigned int matrix_size)
{
   for (int i = 0; i < matrix_size; i++){
      matrix_ptr[i][i] = 1 - matrix_ptr[i][i];
      for (int j = 0; j < i; j++){
         matrix_ptr[i][j] = 0 - matrix_ptr[i][j];
      }
      for (int j = i+1; j < matrix_size; j++){
         matrix_ptr[i][j] = 0 - matrix_ptr[i][j];
      }
   }
}
// ***************** END OF MATRIX OPERATIONS **********************************

int init_settings(int argc, char **argv, pca_basic_settings_t &settings, ostringstream &err_msg){
	char opt;

	ifstream in_file;
	ostringstream string_format;
	string contents;

	size_t start_pos = 0, end_pos = 0;

	uint32_t par_window_size = 0;

	settings.in_unirec_specifier = (char *)DEFAULT_UNIREC_SPECIFIER;
	settings.out_unirec_specifier = (char *)DEFAULT_UNIREC_SPECIFIER_DETECTION;

	settings.path_to_settings = DEFAULT_PATH_TO_SETTINGS;
	settings.working_timebin_window_size = DEFAULT_WORKING_TIMEBIN_WINDOW_SIZE;

   while ((opt = getopt(argc, argv, "s:u:w:")) != -1) {
      switch (opt) {
         case 's':
            settings.path_to_settings = optarg;
            break;
         case 'u':
            settings.in_unirec_specifier = optarg;
            break;
			case 'w':
				par_window_size = atoi(optarg);
//				sscanf(optarg,"%u",par_window_size);
				break;
         default:
            err_msg << "Invalid arguments.\n";
            return 2;
      }
   }

   if (optind > argc) {
      err_msg << "Wrong number of parameters.\n Usage: " << argv[0] << " -i trap-ifc-specifier [-u \"UNIREC,FIELDS\"]"
				" [-s path/to/setting/file]\n";
      return 2;
   }

   in_file.open(settings.path_to_settings.c_str(), ios::in | ios::binary);
	if (!in_file.is_open()){
		err_msg << "Unable to open setting file: " << settings.path_to_settings;
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
		err_msg << "No link count founded. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[0] << "\")";
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
					err_msg << "Bad link names format. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[1] <<"\")";
					return 4;
				}
			}
		}else{
			err_msg << "No link name list. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[1] <<"\")";
			return 4;
		}
	}else{
		err_msg << "Link count is empty. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[0] <<"\")";
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
	// set data matrix width
	settings.data_matrix_width = settings.link_count * settings.agreg_unit_per_link;
	// set working timebin window size
	if (par_window_size){
		settings.working_timebin_window_size = par_window_size;
	}else{
		if ((start_pos = contents.find(SETTINGS_OPTION[3])) != string::npos){
			end_pos = contents.find("\n", start_pos);
			string_format.str("");
			string_format.clear();
			string_format << SETTINGS_OPTION[3] << "%u";
			sscanf(contents.substr(start_pos, end_pos - start_pos).c_str(),
					 string_format.str().c_str(), &settings.working_timebin_window_size);
		}
	}

	return 0;
}

int main(int argc, char **argv)
{
	#ifdef LOG_TO_FILE
	ofstream log;
	log.open(LOG_TO_FILE);
	if (!log.is_open()){
		cerr << "ERROR while opening log file <" << LOG_TO_FILE << ">\n" << flush;
	}
	#endif
	ofstream detection_log;

   int ret;
   ostringstream error_message;
   trap_ifc_spec_t ifc_spec;

	pca_basic_settings_t settings;

	uint8_t timebin_init_flag = 1;
   uint32_t timebin_counter = 0;
   uint32_t actual_timebin_num;
   uint32_t timebin_num;
   uint64_t *rcv_checker;
   uint64_t all_link_flag;
   uint64_t link_bit_field;
   uint16_t link_index;
   uint16_t write_col_selector;
   uint32_t row_selector;

   int need_more_timebins;

	float **raw_data_matrix;
	real_2d_array data_matrix;
   real_2d_array principal_components;
	real_1d_array eigenvalues;
   ae_int_t info;
   #ifdef NSS_BY_DELTA_TEST
   float *data2pc_projection;
   data2pc_projection;
   float norm, delta_threshold;
   unsigned int wi;
   #endif
////   #elif defined NSS_BY_PERCENTAGE
//   #ifdef NSS_BY_PERCENTAGE
   float variance_threshold, sum_variance;
//   #endif//NSS definition
   uint16_t normal_subspace_size;
   float **lin_op_c_residual;
   float *mapped_data;

	float stdev;

	#ifdef SPE_TEST
   float phi [3];
   float lambda, SPE, h0, delta_SPE;
   uint8_t anomaly_detetected;
   #endif //SPE_TEST

	#ifdef MULTI_TEST
	uint32_t anomaly_counter[NSS_DEF_CNT];
	for (int i = 0; i < NSS_DEF_CNT; i++)anomaly_counter[i] = 0;
	float phi [3];
   float lambda, SPE, h0, delta_SPE;
   uint8_t anomaly_detetected;

   uint16_t skip_flag;
   uint16_t nss[NSS_DEF_CNT];
   uint64_t anomaly_flag_field;
   uint16_t **anomaly_identification_fields;
   uint16_t real_anomaly;

   ostringstream output_line, real_anom_output_line;
   ofstream detection_log_values ("anomaly-detection-values-log.txt");
	ofstream anomaly_log ("multi-test_anomaly_log.txt");
	anomaly_log << endl;
   anomaly_log.close();
   ofstream real_anomaly_log ("multi-test_REAL_anomaly_log.txt");
	real_anomaly_log << endl;
   real_anomaly_log.close();
   #endif//MULTI_TEST

   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      cerr << "ERROR in parsing of parameters for TRAP: " << trap_last_error_msg << endl;
      return 1;
   }

   ret = init_settings (argc, argv, settings, error_message);
	if(ret){
		cerr << "Error while initializing module:\n\t" << error_message.str() << endl;
		return ret;
	}

/* SETTINGS CHECK
	cout << "Path to settings file: [" << settings.path_to_settings << "]\n";
	cout << "In UniRec: [" << settings.in_unirec_specifier << "]\n";
	cout << "Out UniRec: [" << settings.out_unirec_specifier << "]\n";
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
	cout << "Data matrix size is: " << settings.working_timebin_window_size << " x " << settings.data_matrix_width << "\n";

	return 0;
*/
   // ***** TRAP initialization *****
   // Initialize TRAP library (create and init all interfaces)
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      cerr << "ERROR in TRAP initialization: " << trap_last_error_msg << endl;
      return 2;
   }

//   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0); //turn off an output buffer

   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);
   // ***** END OF TRAP initialization *****

   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();

   // ***** Create UniRec templates & allocate memory for output records *****
   ur_template_t *in_tmplt = ur_create_template(settings.in_unirec_specifier);

   ur_template_t *out_tmplt = ur_create_template(settings.out_unirec_specifier);

   void *out_rec = ur_create(out_tmplt, 0);
   // ***** END OF Create UniRec templates & allocate memory for output records *****
	// ***** Memory allocation and some initialization *****
	#ifdef MULTI_TEST
	anomaly_identification_fields = new uint16_t *[DELTA_TESTNIG_CNT];
   for (int i = 0; i < DELTA_TESTNIG_CNT; i++){
		anomaly_identification_fields[i] = new uint16_t [settings.data_matrix_width];
	}
	#endif//MULTI_TEST
	rcv_checker = new uint64_t [RCV_OUT_OF_TIMEBIN_TOLERANCE];
	memset(rcv_checker, 0, sizeof(rcv_checker[0]) * RCV_OUT_OF_TIMEBIN_TOLERANCE);

	all_link_flag = 1;
	for (int i = 0; i < settings.link_count; i++){//2^link_count
		all_link_flag *= 2;
	}
	--all_link_flag;

	raw_data_matrix = new float *[settings.working_timebin_window_size];
	for (int i = 0; i < settings.working_timebin_window_size; i++){
		raw_data_matrix[i] = new float [settings.data_matrix_width];
	}
	data_matrix.setlength(settings.working_timebin_window_size, settings.data_matrix_width);
	principal_components.setlength(settings.data_matrix_width, settings.data_matrix_width);
	eigenvalues.setlength(settings.data_matrix_width);
	lin_op_c_residual = new float *[settings.data_matrix_width];
	for (int i = 0; i < settings.data_matrix_width; i++){
		lin_op_c_residual[i] = new float [settings.data_matrix_width];
	}
   mapped_data = new float [settings.data_matrix_width];
   #ifdef NSS_BY_DELTA_TEST
   data2pc_projection = new float [settings.working_timebin_window_size];
   #endif//NSS_BY_DELTA_TEST

	need_more_timebins = settings.working_timebin_window_size;

	detection_log.open(ANOMALY_LOG_NAME);
	detection_log<<"PCA-sketch anomaly detection log file\n";
	detection_log.close();
	// ***** END OF Memory allocation and some initialization *****
	#ifdef MULTI_TEST
	// ***** Fill detection log header *****
	detection_log.open("multi-test_detection_log.txt");
	detection_log << "For every of " << NSS_DEF_CNT << " normal subspace definitions:\n";
	detection_log << "\tnss by percentage: ";
	for (int i = 0; i < 4; i++){
		detection_log << NSS_BY_PERCT_MULTIPLER(i)*100 << "% ";
	}
	#ifdef NSS_BY_DELTA_TEST
	detection_log << "\tnss by DELTA-test: ";
	for (int i = 4; i < NSS_DEF_CNT; i++){
		detection_log << i - 1 << "D ";
	}
	#endif
	detection_log << "\nDetect anomalies by " << DETECTION_TEST_CNT << " tests:\n";
	detection_log << "By new std DELTA-test for: ";
	for (int i = 0; i < DELTA_TESTNIG_CNT; i++){
		detection_log << DETECTION_THRESHOLD_MULTIPLIER(i) << "D ";
//		detection_log << (STARTING_DETECTION_THRESOLD + (i * DETECTION_THRESHOLD_INCREMENT)) << "D ";
	}
	#ifdef SPE_TESTING
	detection_log << " and by SPE-test for alpha-percentile: ";
	for (int i = 0; i < A_PERCENTILE_DEF_CNT; i++){
		detection_log << A_PERC_NAMES[i] << " ";
	}
	#endif//SPE_TESTING
	detection_log << endl;
	detection_log.close();
	// ***** END OF Fill detection log header *****
	#endif//MULTI_TEST
// ***** Main processing loop *****
   while (!stop) {
		// ***** Get input data *****
		const void *in_rec;
		uint16_t in_rec_size;

		// Receive data from any input interface, wait until data are available
		ret = trap_get_data(TRAP_MASK_ALL, &in_rec, &in_rec_size, TRAP_WAIT);
		// Handle possible errors
		TRAP_DEFAULT_GET_DATA_ERROR_HANDLING(ret, continue, break);

		// Check size of received data
		if (in_rec_size < ur_rec_static_size(in_tmplt)){
			stop = 1;
			if (in_rec_size <= 1) {
				break; // End of data (used for testing purposes)
			} else {
				cerr << "Error: data with wrong size received (expected size: >= "
						<< ur_rec_static_size(in_tmplt) << "hu, received size: " << in_rec_size << "u)" << endl;
				break;
			}
		}
		// ***** END OF Get input data *****
		// ***** Process the data *****
		if(timebin_init_flag){
			actual_timebin_num = ur_get(in_tmplt, in_rec, UR_TIMESLOT);
			timebin_init_flag = 0;
		}

		timebin_num = ur_get(in_tmplt, in_rec, UR_TIMESLOT);

		if (timebin_num > (actual_timebin_num + RCV_OUT_OF_TIMEBIN_TOLERANCE) || timebin_num < actual_timebin_num){
			cerr << "Received unexpected timebin number: " << timebin_num << "(expected is: " << actual_timebin_num
			<< " - " << actual_timebin_num + RCV_OUT_OF_TIMEBIN_TOLERANCE << ")." << endl;
			stop = 1;
			continue;
		}
		if (rcv_checker[actual_timebin_num % RCV_OUT_OF_TIMEBIN_TOLERANCE] == all_link_flag){//data for all links and one timebin was readed
			rcv_checker[actual_timebin_num % RCV_OUT_OF_TIMEBIN_TOLERANCE] = 0;
			++actual_timebin_num;
			++timebin_counter;
			--need_more_timebins;
		}
		link_bit_field = ur_get(in_tmplt, in_rec, UR_LINK_BIT_FIELD);
		rcv_checker[timebin_num % RCV_OUT_OF_TIMEBIN_TOLERANCE] |= link_bit_field;
		for (int i = 0; i < settings.link_count; i++){
			if ((link_bit_field >> i) & (uint64_t) 1){
				link_index = i;
				break;
			}
		}
////		cout << "\t" << timebin_num << ". tb - index: "<< link_index <<
////		 " (link-bit-field: " << link_bit_field << "link-checker: " << rcv_checker[timebin_num % RCV_OUT_OF_TIMEBIN_TOLERANCE]
////		 << " = " << all_link_flag  <<")." << endl;
		write_col_selector = 0;
		row_selector = timebin_num % settings.working_timebin_window_size;
		if (settings.agreg_unit_field & MASK_BIT(AU_FLOWS)){
			raw_data_matrix[row_selector][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_FLOWS);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_PACKETS)){
			raw_data_matrix[row_selector][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_PACKETS);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_BYTES)){
			raw_data_matrix[row_selector][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_BYTES);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_ESIP)){
			raw_data_matrix[row_selector][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_ENTROPY_SRCIP);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_EDIP)){
			raw_data_matrix[row_selector][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_ENTROPY_DSTIP);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_ESPORT)){
			raw_data_matrix[row_selector][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_ENTROPY_SRCPORT);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_EDPORT)){
			raw_data_matrix[row_selector][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_ENTROPY_DSTPORT);
			write_col_selector += settings.link_count;
		}

		// *** Detection part ***
		if (!need_more_timebins){
			STATUS_MSG(LOG_DST,">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
			STATUS_MSG(LOG_DST,"Data matrix is completed - starting detection...\n")

			++need_more_timebins;

			// ** Matrix normalization **
			transform_matrix_zero_mean(raw_data_matrix,&data_matrix);
			transform_submatrix_unit_energy(&data_matrix, 0, settings.link_count);
			transform_submatrix_unit_energy(&data_matrix, settings.link_count, 2 * settings.link_count);
			transform_submatrix_unit_energy(&data_matrix, 2 * settings.link_count, 3 * settings.link_count);
			transform_submatrix_unit_energy(&data_matrix, 3 * settings.link_count, 4 * settings.link_count);
			transform_submatrix_unit_energy(&data_matrix, 4 * settings.link_count, 5 * settings.link_count);
			transform_submatrix_unit_energy(&data_matrix, 5 * settings.link_count, 6 * settings.link_count);
			transform_submatrix_unit_energy(&data_matrix, 6 * settings.link_count, 7 * settings.link_count);

			// ** Computing of PCA **
			STATUS_MSG(LOG_DST,"\t  Computing PCA.\n")
			pcabuildbasis(data_matrix, settings.working_timebin_window_size, settings.data_matrix_width, info, eigenvalues, principal_components);
			if(info != 1){
				cerr << "Error while computing PCA (error code: " << info << ")" << endl << flush;
				stop = 1;
				break;
			}
			// ** END OF Computing of PCA **

			#ifdef VALIDATION
			STATUS_MSG(LOG_DST,"\t  Printing validation outputs...\n")
			if(!(timebin_counter % 500)){
//			if(1){
				filename.str("");
				filename.clear();
				filename << "RAWxDMxPCA-special" << timebin_counter;
				ofs.open(filename.str().c_str());
				for (int i = 0; i < data_matrix.rows(); i++){
					for (int j = 0; j < data_matrix.cols(); j++){
						ofs << raw_data_matrix[i][j] << "\t";
					}
					ofs << endl;
				}
				ofs.close();
				filename.str("");
				filename.clear();
				filename << "DMxPCA" << timebin_counter;
				ofs.open(filename.str().c_str());
				for (int i = 0; i < data_matrix.rows(); i++){
					for (int j = 0; j < data_matrix.cols(); j++){
						ofs << data_matrix(i,j) << "\t";
					}
					ofs << endl;
				}
				ofs.close();
				filename.str("");
				filename.clear();
				filename << "PCS" << timebin_counter;
				ofs.open(filename.str().c_str());
				for (int i = 0; i < data_matrix.cols(); i++){
					for (int j = 0; j < data_matrix.cols(); j++){
						ofs << principal_components(i,j) << "\t";
					}
					ofs << endl;
				}
				ofs.close();
				filename.str("");
				filename.clear();
				filename << "ExPCA" << timebin_counter;
				ofs.open(filename.str().c_str());
					for (int j = 0; j < eigenvalues.length(); j++){
						ofs << eigenvalues(j) << "\t";
					}
					ofs << endl;
				ofs.close();
			}
//			stop = 1;
//			break;
			#endif//VALIDATION

			#ifdef MULTI_TEST
			STATUS_MSG(LOG_DST,"\t  Starting MULTI-TEST.\n")
///********************************************************************************************************************************
			detection_log.open("multi-test_detection_log.txt", ios::in | ios::app);
			detection_log << "----------------------------------------------------------------------------------------------" << endl;
			detection_log << timebin_counter << ".timebin" << endl;
			detection_log.close();
///********************************************************************************************************************************
///************************************************************************************************************************
/// NSS DEFINITION ********************************************************************************************************
			STATUS_MSG(LOG_DST,"\t  Finding first 4 NSS ")

			for (int i = 0; i < 4; i++){// NSS by DELTA-TEST
				sum_variance = 0;

				for (int j = 0; j < eigenvalues.length(); j++){
					sum_variance += eigenvalues(j);
				}
				variance_threshold = sum_variance * NSS_BY_PERCT_MULTIPLER(i);

				normal_subspace_size = eigenvalues.length();// data_matrices[i].cols() == eigenvalues.length() == data_matrix_width
				while(sum_variance > variance_threshold){
					sum_variance -= eigenvalues(--normal_subspace_size);
				}
				normal_subspace_size++;
				nss[i] = normal_subspace_size;
			}

			#ifdef NSS_BY_DELTA_TEST
			STATUS_MSG(LOG_DST,"& next " << NSS_DEF_CNT - 4 << " NSS.\n")

			for (int i = 4; i < NSS_DEF_CNT; i++){// NSS BY ORIGINAL-TEST

				normal_subspace_size = 0;
				wi = 0;
				while (!normal_subspace_size && (wi < settings.data_matrix_width)){
					multiply_matrix_column_vector(&data_matrix, &principal_components, wi, data2pc_projection);
					norm = norm_of_vector(data2pc_projection, settings.working_timebin_window_size);
					divide_vector_by_value(data2pc_projection, settings.working_timebin_window_size, norm);
					delta_threshold = vector_standard_deviation_v2(data2pc_projection, settings.working_timebin_window_size);

					delta_threshold *= i - 1; // 3, 4, 5
					for (int k = 0; k < settings.working_timebin_window_size; k++){//"Delta" test
		//                     if (fabs(data2pc_projection[k]) >= NSS_BY_DELTA_TEST * delta_threshold){
						if(data2pc_projection[k] >= delta_threshold || data2pc_projection[k] <= -delta_threshold){
							normal_subspace_size = wi;
						}
					}
					wi++;
				}
				nss[i] = normal_subspace_size;
			}
			#else//NSS_BY_DELTA_TEST
			STATUS_MSG(LOG_DST,"\n")
			#endif//NSS_BY_DELTA_TEST
/// END OF NSS DEFINITION ********************************************************************************************************
///************************************************************************************************************************
/// DETECTION *************************************************************************************************************

			STATUS_MSG(LOG_DST,"\t  Starting anomaly detection.\n")

			anomaly_log.open("multi-test_anomaly_log.txt", ios::in | ios::app);
			anomaly_log << "==================================================================================\n";
			anomaly_log << "Anomaly(ies) in timebin " << timebin_counter << endl;
			anomaly_log.close();

			real_anom_output_line.str("");
			real_anom_output_line.clear();
			real_anom_output_line << "==================================================================================\n";
			real_anom_output_line << "Anomaly(ies) in timebin " << timebin_counter << endl;

			detection_log_values << "==================================================================================\n";
			detection_log_values << "Detection values in timebin " << timebin_counter << endl;

			for (int i = 0; i < NSS_DEF_CNT; i++){//for every NSS definition
				detection_log_values << "-----------------------------------------------------------------------------------\n";
				detection_log_values << "\tFor NSS-def ";
				if (i < 4){
					detection_log_values << NSS_BY_PERCT_MULTIPLER(i) * 100 << "%" << endl;
				}else{
					detection_log_values << i - 1 << "D" << endl;
				}

				anomaly_flag_field = 0;
				output_line << i << ".nss = " << nss[i] << "\t";
/*
				skip_flag = 0;
				for (int j = 0; j < i; j++){//There could be a different identification part
					if (nss[i] == nss[j]){
						output_line << "x"<< j << "\t(was allready tested by " << j << ")";//i was allready tested by j
						if(anomaly_flag_field |= MASK_BIT(j)){
							anomaly_flag_field |= MASK_BIT(i);
						}
						skip_flag = 1;
						break;
					}
				}*/

				if (!skip_flag){
					//** Computiing of linear operator C-residual (performs linear projection onto the anomaly subspace) **
					multiply_submatrix_by_transposed_submatrix(&principal_components, nss[i], lin_op_c_residual);
					substitute_from_identity_matrix(lin_op_c_residual, settings.data_matrix_width);
					// ** END OF Computing of linear operator C-residual ***

					multiply_matrix_by_transposed_line(lin_op_c_residual, settings.data_matrix_width, &data_matrix,
																  timebin_counter % settings.working_timebin_window_size, mapped_data); // in  OLD SPE TEST  too
/// STDEV TESTING *********************************************************************************************************
					STATUS_MSG(LOG_DST,"\t\t By std-dev testing....\n")

					stdev = vector_standard_deviation_v2(mapped_data, settings.data_matrix_width);

					detection_log_values << "\t\tSTD-DEV testing: " << endl;
					detection_log_values << "\t\t  std-dev = " << stdev << endl;
/// ##################### 2. DETECTION CYCLE 0 - DELTA_TESTNIG_CNT ##############
					for (int k = 0; k < DELTA_TESTNIG_CNT; k++){
						for (int l = 0; l < settings.data_matrix_width; l++){

							if((mapped_data[l] > (stdev * DETECTION_THRESHOLD_MULTIPLIER(k))) ||
								 (mapped_data[l] < -(stdev * DETECTION_THRESHOLD_MULTIPLIER(k)))){

								anomaly_flag_field |= MASK_BIT(k);
								anomaly_identification_fields[k][l] = 1;

								detection_log_values << "\t\t  for delta = " << DETECTION_THRESHOLD_MULTIPLIER(k)
															<< "(" << k << "): "<< l << ". anomalous value = " << mapped_data[l] << endl;
							}
						}
					}//for{} 2. detection cycle
/// END OF STDEV TESTING *********************************************************************************************************
					#ifdef SPE_TESTING
///SPE TESTING ************************************************************************************************************
					STATUS_MSG(LOG_DST,"\t\t By SPE testing....\n")

					SPE = norm_of_vector(mapped_data, settings.data_matrix_width);
					SPE *= SPE;

					detection_log_values << "\t\tSPE-testing: " << endl;
					detection_log_values << "\t\t  SPE = " << SPE << endl;

					// ** Detecting anomalies by "SPE" test **
					phi[0] = 0;
					phi[1] = 0;
					phi[2] = 0;

					for (int j = nss[i]; j < settings.data_matrix_width; j++){
						lambda = eigenvalues(j);
						phi[0] += lambda;
						lambda *= lambda;
						phi[1] += lambda;
						lambda *= lambda;
						phi[2] += lambda;
					}
					h0 = 1.0 - ((2.0 * phi[0] * phi[2]) / (3.0 * phi[1] * phi[1]));
/// ##################### 1. DETECTION CYCLE 0 - A_PERCENTILE_DEF_CNT ###################################################
					for (int k = 0; k < A_PERCENTILE_DEF_CNT; k++){
						delta_SPE = phi[0] * pow((
									((A_PERCENTILES[k] * sqrt(2.0 * phi[1] * h0 * h0)) / phi[0])
									+ 1.0 + ((phi[1] * h0 * (h0 - 1.0)) / (phi[0] * phi[0])) ),(1.0/h0));

						detection_log_values << "\t\t  " << k << ".[delta]-spe = " << delta_SPE << endl;
						if (SPE > delta_SPE){
							anomaly_flag_field |= MASK_BIT(k + DELTA_TESTNIG_CNT);
						}
					}//for{} 1. detection cycle
/// END OF SPE TESTING ************************************************************************************************************
					#endif//SPE_TESTING

					real_anomaly = 0;

					if (anomaly_flag_field){
						anomaly_log.open("multi-test_anomaly_log.txt", ios::in | ios::app);
						anomaly_log << "\tNSS variant " << i << endl;
						if(anomaly_flag_field & DETECTION_SELECTOR){
							real_anom_output_line << "\tNSS variant " << i << endl;
							real_anomaly = 1;
						}

						++anomaly_counter[i];

						for (int j = 0; j < DETECTION_TEST_CNT; j++){
							if(anomaly_flag_field & MASK_BIT(j)){
								output_line << "1 ";

								if (j < DELTA_TESTNIG_CNT){//select only delta-testing part, where identification is availadble
									anomaly_log << "\t\t" << "Detection by " << DETECTION_THRESHOLD_MULTIPLIER(j)
													<< "D (" << nss[i] <<"):\t\t";

									if(real_anomaly){
										real_anom_output_line << "\t\t" << "Detection by " << DETECTION_THRESHOLD_MULTIPLIER(j)
													<< "D (" << nss[i] <<"):\t\t";
									}

									for (int l = 0; l < settings.data_matrix_width; l++){
										if (anomaly_identification_fields[j][l]){
											anomaly_log << l << "(" << settings.link_names[l%settings.link_count]
															<< "-au." << l/settings.link_count <<")";

											if(real_anomaly){
												real_anom_output_line << l << "(" << settings.link_names[l%settings.link_count]
																	  << "-au." << l/settings.link_count <<")";
											}

											anomaly_identification_fields[j][l] = 0;
										}
									}
									anomaly_log << endl;
									if(real_anomaly){
										real_anom_output_line << endl;
									}
								}
							}else{
								output_line << "0 ";
							}
							if(!(j % 5) && j){
								output_line << " | ";
							}
						}//for{} anomaly vector iteration

						anomaly_log << "------------------------------------------------------------" << endl;
						anomaly_log.close();
						if(real_anomaly){
							real_anom_output_line << "------------------------------------------------------------" << endl;
						}

						#ifdef VALIDATION
						if (output_counter <= OUTPUT_LIMITER && i == 0){
							++output_counter;
							filename.str("");
							filename.clear();
							filename << "RAWxDMxPCA" << timebin_counter;
							ofs.open(filename.str().c_str());
							for (int i_val = 0; i_val < data_matrix.rows(); i_val++){
								for (int j_val = 0; j_val < data_matrix.cols(); j_val++){
									ofs << raw_data_matrix[i_val][j_val] << "\t";
								}
								ofs << endl;
							}
							ofs.close();
							filename.str("");
							filename.clear();
							filename << "DMxPCA" << timebin_counter;
							ofs.open(filename.str().c_str());
							for (int i_val = 0; i_val < data_matrix.rows(); i_val++){
								for (int j_val = 0; j_val < data_matrix.cols(); j_val++){
									ofs << data_matrix(i_val,j_val) << "\t";
								}
								ofs << endl;
							}
							ofs.close();
							filename.str("");
							filename.clear();
							filename << "PCS" << timebin_counter;
							ofs.open(filename.str().c_str());
							for (int i_val = 0; i_val < data_matrix.cols(); i_val++){
								for (int j_val = 0; j_val < data_matrix.cols(); j_val++){
									ofs << principal_components(i_val,j_val) << "\t";
								}
								ofs << endl;
							}
							ofs.close();
							filename.str("");
							filename.clear();
							filename << "ExPCA" << timebin_counter;
							ofs.open(filename.str().c_str());
							for (int j_val = 0; j_val < eigenvalues.length(); j_val++){
								ofs << eigenvalues(j_val) << "\t";
							}
							ofs << endl;
							filename.str("");
							filename.clear();
							filename << "CRxPCAx" << timebin_counter << "NSS" << nss[i];
							ofs.open(filename.str().c_str());
							for (int i_val = 0; i_val < settings.data_matrix_width; i_val++){
								for (int j_val = 0; j_val < settings.data_matrix_width; j_val++){
									ofs << lin_op_c_residual[i_val][j_val] << "\t";
								}
								ofs << endl;
							}
							ofs.close();
						}
						#endif//VALIDATION
					}else{//if{} there is some anomaly
						output_line << "no anomaly";
					}//if-else{} - threre is NOT an anomaly
				}//if{} NOT skip_flag

				detection_log.open("multi-test_detection_log.txt", ios::in | ios::app);
				detection_log << output_line.str() << endl;
				detection_log.close();

				if (real_anomaly){
					real_anomaly_log.open("multi-test_REAL_anomaly_log.txt", ios::in | ios::app);
					real_anomaly_log << real_anom_output_line.str();
					real_anomaly_log.close();
				}

				output_line.str("");
				output_line.clear();
			}//for{} every NSS definition
			#endif //MULTI_TEST

/// END OF DETECTION *************************************************************************************************************
///************************************************************************************************************************

/////** PRE_MULTI-TEST PART*********************************************************/
//{//folding
////			// ** Finding of normal subspace size **
//////			t2 = clock();//new-testing
////			#ifdef NORMAL_SUBSPACE_SIZE_FIXED
////			normal_subspace_size = NORMAL_SUBSPACE_SIZE_FIXED;
////			#elif defined NSS_BY_PERCENTAGE
////			sum_variance = 0;
////
////			for (int j = 0; j < eigenvalues.length(); j++){
////				sum_variance += eigenvalues(j);
////			}
////			variance_threshold = sum_variance * NSS_BY_PERCENTAGE;
////
////			normal_subspace_size = eigenvalues.length();// data_matrices[i].cols() == eigenvalues.length() == data_matrix_width
////			while(sum_variance > variance_threshold){
////				sum_variance -= eigenvalues(--normal_subspace_size);
////			}
////			normal_subspace_size++;
////			#else// !NSS_BY_PERCENTAGE && !NORMAL_SUBSPACE_SIZE_FIXED
////			normal_subspace_size = 0;
////			wi = 0;
////			while (!normal_subspace_size && (wi < data_matrix_width)){
////				multiply_matrix_column_vector(&data_matrix, &principal_components, wi, data2pc_projection);
////				norm = norm_of_vector(data2pc_projection, working_timebin_window_size);
////				divide_vector_by_value(data2pc_projection, working_timebin_window_size, norm);
////				#if defined STD_DEV
////				delta_threshold = STD_DEV;
////				#elif defined STD_DEV_VERSION2
////				delta_threshold = vector_standard_deviation_v2(data2pc_projection, working_timebin_window_size);
////				#else//STD_DEV selection
////				delta_threshold = vector_standard_deviation(data2pc_projection, working_timebin_window_size);
////				#endif//STD_DEV selection
////
////				delta_threshold *= NSS_BY_DELTA_TEST;
////				for (int k = 0; k < working_timebin_window_size; k++){//"Delta" test
////   //                     if (fabs(data2pc_projection[k]) >= NSS_BY_DELTA_TEST * delta_threshold){
////					if(data2pc_projection[k] >= delta_threshold || data2pc_projection[k] <= -delta_threshold){
////						normal_subspace_size = wi;
////					}
////				}
////				wi++;
////			}
////			#endif//NSS definition
//////			STATUS_MSG(LOG_DST,"\t\tFinding NSS: (" << (clock() - t2) / CLOCKS_PER_SEC << " sec)\n")//new-testing
////			STATUS_MSG(LOG_DST,"\t  Normal subspace size is: " << normal_subspace_size << "\n")
////
////			// ** Computiing of linear operator C-residual (performs linear projection onto the anomaly subspace) **
//////			t2 = clock();//new-testing
////			multiply_submatrix_by_transposed_submatrix(&principal_components, normal_subspace_size, lin_op_c_residual);
////			substitute_from_identity_matrix(lin_op_c_residual, data_matrix_width);
////			// ** END OF Computing of linear operator C-residual ***
////			#ifdef VALIDATION
////			if(timebin_counter == 501){
////				ofs.open("PCS-PCA");
////				for (int i = 0; i < data_matrix.cols(); i++){
////					for (int j = 0; j < data_matrix.cols(); j++){
////						ofs << principal_components(i,j) << "\t";
////					}
////					ofs << endl;
////				}
////				ofs.close();
////				ofs.open("CR-PCA");
////				for (int i = 0; i < data_matrix.cols(); i++){
////					for (int j = 0; j < data_matrix.cols(); j++){
////						ofs << lin_op_c_residual[i][j] << "\t";
////					}
////					ofs << endl;
////				}
////				ofs.close();
////				ofs.open("E-PCA");
////					for (int j = 0; j < eigenvalues.length(); j++){
////						ofs << eigenvalues(j) << "\t";
////					}
////					ofs << endl;
////				ofs.close();
////			}
////			#endif//VALIDATION
////			cout << round_timebin_counter << "   ";
////			multiply_matrix_by_transposed_line(lin_op_c_residual, data_matrix_width, &data_matrix, round_timebin_counter, mapped_data); // in  OLD SPE TEST  too
/////**>>>>>>>****** OLD SPE TEST ****************************************************************************************/
////			#ifdef SPE_TEST
////			SPE = norm_of_vector(mapped_data, data_matrix_width);
////
////			SPE *= SPE;
//////			STATUS_MSG(LOG_DST,"\t\tComputing Cres & SPE: (" << (clock() - t2) / CLOCKS_PER_SEC << " sec)\n")//new-testing
////
////			STATUS_MSG(LOG_DST,"\t  Starting SPE test.\n")
////
////			// ** Detecting anomalies by "SPE" test **
//////			t2 = clock();//new-testing
////			phi[0] = 0;
////			phi[1] = 0;
////			phi[2] = 0;
////
////			for (int j = normal_subspace_size; j < data_matrix_width; j++){
////				lambda = eigenvalues(j);
////				phi[0] += lambda;
////				lambda *= lambda;
////				phi[1] += lambda;
////				lambda *= lambda;
////				phi[2] += lambda;
////			}
////			h0 = 1.0 - ((2.0 * phi[0] * phi[2]) / (3.0 * phi[1] * phi[1]));
////			delta_SPE = phi[0] * pow((
////							((ALPHA_PERCENTILE_95 * sqrt(2.0 * phi[1] * h0 * h0)) / phi[0])
////							+ 1.0 + ((phi[1] * h0 * (h0 - 1.0)) / (phi[0] * phi[0])) ),(1.0/h0));
////			STATUS_MSG(LOG_DST,"phi1: " << phi[0] << " | phi2: " << phi[1] << " | phi3: " << phi[2]<< " | h0: " << h0 << "\n")
//////			STATUS_MSG(LOG_DST,SPE << "   ?>?   " << delta_SPE)
////			if (SPE > delta_SPE){
////				anomaly_detetected++;
////				STATUS_MSG(LOG_DST,"\t  ## !!! ## Anomaly in timebin No." << timebin_counter << " !!!\n")
////			} else {
//////				STATUS_MSG(LOG_DST,"\t  ## NO ## Anomaly in timebin No." << timebin_counter << "\n")
////			}
//////			STATUS_MSG(LOG_DST,"\t\tSPE test: (" << (clock() - t2) / CLOCKS_PER_SEC << " sec)\n")//new-testing
////			// ** END OF Detecting anomalies by "SPE" test **
////			#endif//SPE_TEST
/////**<<<<<<********* END OF OLD SPE TEST ****************************************************************************************/
////		}
////		stdev = vector_standard_deviation_v2(mapped_data, data_matrix_width);
////		for (int i = 0; i < data_matrix_width; i++){
////			if( (mapped_data[i] > (stdev * DEFAULT_DETECTION_THRESHOLD)) ||
////				 (mapped_data[i] < -(stdev * DEFAULT_DETECTION_THRESHOLD)) ){
//////				STATUS_MSG(LOG_DST,"\t  ## !!! ## Anomaly in timebin No." << timebin_counter << " !!!\n")
////				cerr << "Anomaly in timebin No." << timebin_counter << endl;
////			}
////		}
////		// *** END OF detection part ***
/////**		STATUS_MSG(LOG_DST,"-\t-\t-\t-\t-\t-\t-\t-\t-\n")
////
////		detection_log.open(detection_log_NAME, ios::in | ios::app);
//////		if (anomaly_detetected){
////			STATUS_MSG(LOG_DST,"There is an anomaly in " << timebin_counter << ".timebin" << ".\n")
////			// Fill output record
////			ur_set(out_tmplt, out_rec, UR_TIME_FIRST, 0000 );
////			ur_set(out_tmplt, out_rec, UR_TIME_LAST, 0000);
////			detection_log << timebin_counter << ".TB: " << "an ANOMALY here !!! " << endl;
//////		}
////		detection_log.close();
////		// Send record to interface 0
////		ret = trap_send_data(0, out_rec, ur_rec_static_size(out_tmplt), TRAP_HALFWAIT);
////		TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0, break);
////
////		STATUS_MSG(LOG_DST,"<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<\n\n")
////*/
//}//folding
/////** END OF  PRE_MULTI-TEST PART*********************************************************/
		}//if{} DO NOT need_more_timebins
   }//<while>
   // ***** END OF Main processing loop *****

   // ***** Cleanup *****
   #ifdef MULTI_TEST
   detection_log_values.close();

   for (int i = 0; i < NSS_DEF_CNT; i++){
		STATUS_MSG(LOG_DST,"For " << i << ".NSS definition: " << anomaly_counter[i] << " anomaly found.\n")
   }

	for (int i = 0; i < DELTA_TESTNIG_CNT; i++){
   	delete [] anomaly_identification_fields[i];
   }
   delete [] anomaly_identification_fields;
	#endif//MULTI_TEST

   #ifdef LOG_TO_FILE
	log.close();
	#endif//LOG_TO_FILE

	delete rcv_checker;

	for (int i = 0; i < settings.data_matrix_width; i++){
		delete [] lin_op_c_residual[i];
	}
   delete [] lin_op_c_residual;

	for (int i = 0; i < settings.working_timebin_window_size; i++){
		delete [] raw_data_matrix[i];
	}
   delete [] raw_data_matrix;

   #ifdef NSS_BY_DELTA_TEST
   delete [] data2pc_projection;
   #endif//NSS_BY_DELTA_TEST
   delete [] mapped_data;

   ur_free(out_rec);
   ur_free_template(out_tmplt);

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(in_tmplt);
   // ***** END OF Cleanup *****

   return 0;

}
// END OF PCA_basic_detector.cpp
