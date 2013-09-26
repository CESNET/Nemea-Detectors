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

//#define VALUES
//#define VALIDATION
#ifdef VALIDATION
#define OUTPUT_LIMITER 40
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
static ostringstream error_msg_buffer;

// Function to handle SIGTERM and SIGINT signals (used to stop the module)
TRAP_DEFAULT_SIGNAL_HANDLER(stop = 1);

/**
 * \brief Procedure computes standard deviation from vector (1st version).
 *
 * Procedure computes standard deviation from vector in two different ways - two
 * versions (according to: http://www.mathworks.com/help/matlab/ref/std.html).
 * \param[in] vector_ptr Pointer to vector.
 * \param[in] vector_size Size of vector.
 * \return Real (float) value of stadard deviation.
 */
float vector_standard_deviation (float *vector_ptr, unsigned int vector_size)
{
   float sum=0;
// Since values are mean-centered = have zero mean -> simplier version:
   for (int i = 0; i < vector_size; i++){
      sum += vector_ptr[i] * vector_ptr[i];
   }
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
   return sqrt(sum / (vector_size - 1));
}
/**
 * \brief Procedure computes standard deviation from matrix column (vector) (2nd version).
 * \param[in] data_matrix Pointer to matrix.
 * \param[in] vector_size Size of vector (data matrix row count).
 * \param[in] column Index of matrix column - "vector of interest".
 * \return Real (float) value of stadard deviation.
 */
float vector_standard_deviation_v2(float **data_matrix, unsigned int vector_size, unsigned int column)
{
   float sum = 0, tmp;
   float mean = 0;

   for (int i = 0; i < vector_size; i++){
      mean += data_matrix[i][column];
   }
   mean /= vector_size;

   for (int i = 0; i < vector_size; i++){
      tmp = data_matrix[i][column] - mean;
      sum += tmp * tmp;
   }
//   return sqrt(sum / (data_matrix->rows()));
   return sqrt(sum / (vector_size - 1));
}
/**
 * \brief Procedure computes standard deviation from matrix column (vector) (2nd version).
 * \param[in] data_matrix Pointer to matrix.
 * \param[in] column Index of matrix column - "vector of interest".
 * \return Real (float) value of stadard deviation.
 */
float vector_standard_deviation_v2(real_2d_array *data_matrix, unsigned int column)
{
   float sum = 0, tmp;
   float mean = 0;

   for (int i = 0; i < data_matrix->rows(); i++){
      mean += (*data_matrix)(i,column);
   }
   mean /= data_matrix->rows();

   for (int i = 0; i < data_matrix->rows(); i++){
      tmp = (*data_matrix)(i,column) - mean;
      sum += tmp * tmp;
   }
//   return sqrt(sum / (data_matrix->rows()));
   return sqrt(sum / (data_matrix->rows() - 1));
}

/**
 * \brief Procedure preprocess data matrix.
 *
 * Procedure finding significant deviations (large anomalies) in data matrix
 * before aplying PCA. This anomalies are reported immediately and they are
 * cropped to mean value (in order not to disturb PCA detection results).
 * \param[in] data_matrix Pointer to matrix.
 * \param[in] actual_timebin Index of matrix row - actual timebin.
 * \return Returns integer (int) error code (0 means OK).
 */
int preprocess_data(real_2d_array *data_matrix, unsigned int actual_timebin, unsigned int *anomaly_identification_field)
{
	float mean, delta_threshold;

	if (actual_timebin >= data_matrix->rows()){
		error_msg_buffer.str("");
		error_msg_buffer.clear();
		error_msg_buffer << "Error while preprocessing data:";
		error_msg_buffer << "\n\tRow index (" << actual_timebin << ") ";
		error_msg_buffer << "is bigger then matrix size(" << data_matrix->rows() << " x " << data_matrix->cols() << ").";
		return 6;
	}

	for(int i = 0; i < data_matrix->cols(); i++){
		mean = 0;//data matrix columns are mean centered (have zero mean)

		delta_threshold = vector_standard_deviation_v2(data_matrix, i);
		delta_threshold *= PREPROCESS_DATA_DEV_MULTIPLIER;

		if ((*data_matrix)(actual_timebin,i) > delta_threshold
			 || (*data_matrix)(actual_timebin,i) < -delta_threshold){

			anomaly_identification_field[i] = 1;
		}

		for(int j = 0; j < data_matrix->rows(); j++){
			if((*data_matrix)(j,i) > delta_threshold
			   || (*data_matrix)(j,i) < -delta_threshold){

				(*data_matrix)(j,i) = mean;
			}
		}
	}

	return 0;
}
// ***************** MATRIX OPERATIONS *****************************************
/**
 * \brief Procedure transforms columns of matrix to have zero mean. This
 * procedured does not change original matrix.
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
 * \brief Procedure transforms submatrix of matrix to have unit energy. This
 * procedure changes original matrix.
 *
 * Procedure transforms submatrix of "matrix_ptr", defined by columns
 * "start_index" and "last_index", to unit energy (last_index is first which
 * IS NOT affected). This procedure changes original matrix.
 * \param[in,out] matrix_ptr Pointer to matrix which contains submatrix which
 * should be normalized.
 * \param[in] start_index First column of submatrix (column of matrix from
 * matrix_ptr).
 * \param[in] last_index Last column of submatrix (first column which is not
 * affected) (column of matrix from matrix_ptr).
 * \return Returns integer (int) error code (0 means OK).
 */
int  transform_submatrix_unit_energy (real_2d_array *matrix_ptr,
                                       uint16_t start_index,
                                       uint16_t last_index)
{
   float energy_of_submatrix = 0.0, stdev_of_submatrix;

   if (start_index >= last_index || last_index > matrix_ptr->rows()){
		error_msg_buffer.str("");
		error_msg_buffer.clear();
		error_msg_buffer << "Error while transorming submatrix to unit energy:";
		error_msg_buffer << "\n\tBad submatrix index(es) (first=" << start_index << ", last=" << last_index << ") passed.";
		return 6;
	}

   for (int i = start_index; i < last_index; i++){
      for (int j = 0; j < matrix_ptr->rows(); j++){
         energy_of_submatrix += (*matrix_ptr)(j,i) * (*matrix_ptr)(j,i);
      }
   }
   energy_of_submatrix /= (matrix_ptr->rows() *  (last_index - start_index));
   stdev_of_submatrix = sqrt(energy_of_submatrix);

   for (int i = start_index; i < last_index; i++){
      for (int j = 0; j < matrix_ptr->rows(); j++){
         (*matrix_ptr)(j,i) /= stdev_of_submatrix;
      }
   }
   return 0;
}

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
 * \return Returns integer (int) error code (0 means OK).
 */
int multiply_submatrix_by_transposed_submatrix (real_2d_array *matrix_ptr,
                                                 uint16_t column_delimiter,
                                                 float **result_ptr)
{
   uint16_t x,y;
   float row_sum;

	if (column_delimiter > matrix_ptr->cols()){
		error_msg_buffer.str("");
		error_msg_buffer.clear();
		error_msg_buffer << "Error while (submatrix * submatrix^T) operation:";
		error_msg_buffer << "\n\tColumn delimiter (" << column_delimiter << ") ";
		error_msg_buffer << " is bigger then matrix size (" << matrix_ptr->rows() << " x " << matrix_ptr->cols() << ").";
		return 6;
	}

   for (int i = 0; i < (matrix_ptr->rows() * matrix_ptr->rows()); i++){
      row_sum = 0;

      x = i / matrix_ptr->rows();
      y = i % matrix_ptr->rows();

      for (int j = 0; j < column_delimiter; j++){
         row_sum += (*matrix_ptr)(x,j) * (*matrix_ptr)(y,j);
      }

      result_ptr[x][y] = row_sum;
   }
   return 0;
}

/**
 * \brief Procedure multiplies matrix and transposed row of another matrix.
 *
 * Procedure multiplies first matrix and transposed row of second matrix defined
 * by parameter (row_selector).
 * \param[in] A_matrix_ptr Pointer to first square matrix.
 * \param[in] A_matrix_size Size of first (square) matrix.
 * \param[in] B_matrix_ptr Pointer to second matrix, which contains row, which
 * is used as column vector (transposed row).
 * \param[in] row_selector Specifies row of B_matrix_ptr.
 * \param[out] result_ptr Pointer to vector for result - size is calculated from
 *  matrix dimensions.
 * \return Returns integer (int) error code (0 means OK).
 */
int multiply_matrix_by_transposed_line (float **A_matrix_ptr,
                                         unsigned int A_matrix_size,
                                         real_2d_array *B_matrix_ptr,
                                         unsigned int row_selector,
                                         float *result_ptr)
{
   uint16_t y;
   float row_sum;

	if (row_selector > B_matrix_ptr->rows()){
		error_msg_buffer.str("");
		error_msg_buffer.clear();
		error_msg_buffer << "Error while (matrix * matrix(i,:)^T) operation:";
		error_msg_buffer << "\n\tRow selector (" << row_selector << ") ";
		error_msg_buffer << "is bigger then matrix size (" << B_matrix_ptr->rows() << " x " << B_matrix_ptr->cols() << ").";
		return 6;
	}
	if (A_matrix_size != B_matrix_ptr->cols()){//checking cols, since vector is transposed
		error_msg_buffer.str("");
		error_msg_buffer.clear();
		error_msg_buffer << "Error while (matrix * matrix(i,:)^T) operation:";
		error_msg_buffer << "\n\tMatrix (" << A_matrix_size << " x " << A_matrix_size << ") ";
		error_msg_buffer << "and vector (" << B_matrix_ptr->cols() << " x " << 1 << ") sizes do not match.";
		return 6;
	}

   for (int i = 0; i < A_matrix_size; i++){
      row_sum = 0;

      y = i;

      for (int j = 0; j < A_matrix_size; j++){
         row_sum += A_matrix_ptr[y][j] * (*B_matrix_ptr)(row_selector,j);
      }

      result_ptr[i] = row_sum;
   }
   return 0;
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
 * \return Returns integer (int) error code (0 means OK).
 */
int multiply_matrix_column_vector (real_2d_array *A_matrix_ptr,
                                    real_2d_array *B_matrix_ptr,
                                    unsigned int B_matrix_column,
                                    float *result)
{
   float row_sum;
	if (B_matrix_column > B_matrix_ptr->cols()){
		error_msg_buffer.str("");
		error_msg_buffer.clear();
		error_msg_buffer << "Error while (matrix * matrix(:,i)) operation:";
		error_msg_buffer << "\n\tColumn selector is bigger then matrix size.";
		return 6;
	}
	if (A_matrix_ptr->cols() != B_matrix_ptr->rows()){
		error_msg_buffer.str("");
		error_msg_buffer.clear();
		error_msg_buffer << "Error while (matrix * matrix(:,i)) operation:";
		error_msg_buffer << "\n\tMatrix and vector sizes do not match.";
		return 6;
	}
   for (int i = 0; i < A_matrix_ptr->rows(); i++){
      row_sum = 0;
      for (int j = 0; j < A_matrix_ptr->cols(); j++){
         row_sum += (*A_matrix_ptr)(i,j) * (*B_matrix_ptr)(j,B_matrix_column);
      }
      result[i] = row_sum;
   }
   return 0;
}

/**
 * \brief Procedure divides vector by value. This procedure changes original
 * vector.
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
 * This procedure changes original matrix.
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
// ***************** END OF MATRIX OPERATIONS **********************************
/**
 * \brief ...
 * \param[in] argc .
 * \param[in] argv .
 * \param[out] settings .
 * \return Returns integer (int) error code (0 means OK).
 */
int init_settings(int argc, char **argv, pca_basic_settings_t &settings){
	char opt;

	ifstream in_file;
	ostringstream string_format;
	string contents, def_link_names;

	size_t start_pos = 0, end_pos = 0, tmp_pos = 0;

	uint32_t par_window_size = 0;

	int tmp_index;
	// set up all settings to default values from PCA_basic.h
	settings.path_to_settings = DEFAULT_PATH_TO_SETTINGS;

	settings.in_unirec_specifier = (char *)DEFAULT_UNIREC_SPECIFIER;
	settings.out_unirec_specifier = (char *)DEFAULT_UNIREC_SPECIFIER_DETECTION;

	settings.link_count = DEFAULT_LINK_COUNT;
	def_link_names = DEFAULT_LINK_NAMES;
	for (int i = 0; i < DEFAULT_LINK_COUNT; i++){
		if ((end_pos = contents.find(",", start_pos + 1)) != string::npos){
			settings.link_names.push_back(contents.substr(++start_pos, --end_pos - start_pos));
			start_pos = end_pos + 1;
		}else{
			error_msg_buffer << "Bad link names format (in default settings).";
			return 4;
		}
	}


	settings.working_timebin_window_size = DEFAULT_WORKING_TIMEBIN_WINDOW_SIZE;
	settings.out_of_timebin_rcv_tolerance = DEFAULT_RCV_OUT_OF_TIMEBIN_TOLERANCE;
	settings.timeslot_increment = DEFAULT_TIMESLOT_INCREMENT;
	settings.preprocessing_flag = DEFAULT_PREPROCESSING_FLAG;
	settings.true_detection_match = DEFAULT_TDM_MATCH_VERSION;
	settings.true_detection_selector = DEFAULT_TDM_SELECTOR;

//	settings.data_matrix_width = def_val; // no need since value is computed from link_count and agreg_units_per_link

//
//	uint16_t agreg_unit_per_link;
//	uint16_t agreg_unit_field;
//	uint16_t *selected_agreg_units;
//	uint16_t data_matrix_width;//used by detector only
//	uint32_t working_timebin_window_size;//used by detector only
//
//	uint16_t out_of_timebin_rcv_tolerance;//used by detector only
//	uint8_t preprocessing_flag;//used by detector only
//	uint8_t true_detection_match;//used by detector only
//	uint64_t true_detection_selector;//used by detector only
//	// end of setting defaults
//
//	"link count=",		//option 0 c
//	"links=",			//option 1 l
//	"agregation=",		//option 2 a
//	"window size=",	//option 3 w
//	"tolerance=",		//option 4 t
//	"preprocessing",	//option 5 P
//	"td match=",		//option 6 m
//	"td selector=",	//option 7 s

   while ((opt = getopt(argc, argv, "s:u:w:")) != -1) {
      switch (opt) {
         case 's':
            settings.path_to_settings = optarg;
            break;
//         case 'u':
//            settings.in_unirec_specifier = optarg;
//            break;
			case 'w':
				par_window_size = atoi(optarg);
//				sscanf(optarg,"%u",par_window_size);
				break;
         default:
            error_msg_buffer << "Invalid arguments.\n";
            return 2;
      }
   }

   if (optind > argc) {
      error_msg_buffer << "Wrong number of parameters.\n Usage: " << argv[0] << " -i trap-ifc-specifier [-u \"UNIREC,FIELDS\"]"
				" [-s path/to/setting/file]\n";
      return 2;
   }

   in_file.open(settings.path_to_settings.c_str(), ios::in | ios::binary);
	if (!in_file.is_open()){
		error_msg_buffer << "Unable to open setting file: " << settings.path_to_settings;
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
		error_msg_buffer << "No link count founded. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[0] << "\")";
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
					error_msg_buffer << "Bad link names format. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[1] <<"\")";
					return 4;
				}
			}
		}else{
			error_msg_buffer << "No link name list. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[1] <<"\")";
			return 4;
		}
	}else{
		error_msg_buffer << "Link count is empty. (see [" << settings.path_to_settings << "] file, option \"" << SETTINGS_OPTION[0] <<"\")";
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
	settings.selected_agreg_units = new unsigned int [settings.agreg_unit_per_link];
	tmp_index = 0;
	if (settings.agreg_unit_field & MASK_BIT(AU_FLOWS)){
		settings.selected_agreg_units[tmp_index] = AU_FLOWS;
//		settings.selected_agreg_units[tmp_index] = UR_FLOWS;
//		settings.selected_agreg_units[settings.agreg_unit_per_link + tmp_index++] = AU_FLOWS;
	}
	if (settings.agreg_unit_field & MASK_BIT(AU_PACKETS)){
		settings.selected_agreg_units[tmp_index] = AU_PACKETS;
//		settings.selected_agreg_units[tmp_index] = UR_PACKETS;
//		settings.selected_agreg_units[settings.agreg_unit_per_link + tmp_index++] = AU_PACKETS;
	}
	if (settings.agreg_unit_field & MASK_BIT(AU_BYTES)){
		settings.selected_agreg_units[tmp_index] = AU_BYTES;
//		settings.selected_agreg_units[tmp_index] = UR_BYTES;
//		settings.selected_agreg_units[settings.agreg_unit_per_link + tmp_index++] = AU_BYTES;
	}
	if (settings.agreg_unit_field & MASK_BIT(AU_ESIP)){
		settings.selected_agreg_units[tmp_index] = AU_ESIP;
//		settings.selected_agreg_units[tmp_index] = UR_ENTROPY_SRCIP;
//		settings.selected_agreg_units[settings.agreg_unit_per_link + tmp_index++] = AU_ESIP;
	}
	if (settings.agreg_unit_field & MASK_BIT(AU_EDIP)){
		settings.selected_agreg_units[tmp_index] = AU_EDIP;
//		settings.selected_agreg_units[tmp_index] = UR_ENTROPY_DSTIP;
//		settings.selected_agreg_units[settings.agreg_unit_per_link + tmp_index++] = AU_EDIP;
	}
	if (settings.agreg_unit_field & MASK_BIT(AU_ESPORT)){
		settings.selected_agreg_units[tmp_index] = AU_ESPORT;
//		settings.selected_agreg_units[tmp_index] = UR_ENTROPY_SRCPORT;
//		settings.selected_agreg_units[settings.agreg_unit_per_link + tmp_index++] = AU_ESPORT;
	}
	if (settings.agreg_unit_field & MASK_BIT(AU_EDPORT)){
		settings.selected_agreg_units[tmp_index] = AU_EDPORT;
//		settings.selected_agreg_units[tmp_index] = UR_ENTROPY_DSTPORT;
//		settings.selected_agreg_units[settings.agreg_unit_per_link + tmp_index++] = AU_EDPORT;
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
	// set "out of timebin" tolerance
	if ((start_pos = contents.find(SETTINGS_OPTION[4])) != string::npos){
		end_pos = contents.find("\n", start_pos);
		string_format.str("");
		string_format.clear();
		string_format << SETTINGS_OPTION[4] << "%u";
		sscanf(contents.substr(start_pos, end_pos - start_pos).c_str(),
				 string_format.str().c_str(), &settings.out_of_timebin_rcv_tolerance);
	}else{
//		settings.out_of_timebin_rcv_tolerance = PAR-DEF;
	}
	// set preprocessing flag
	if ((start_pos = contents.find(SETTINGS_OPTION[5])) != string::npos){
		tmp_pos = start_pos;
		end_pos = contents.find("\n", start_pos);
		if ((start_pos = contents.find("yes", start_pos)) != string::npos){
			if (start_pos < end_pos){
				settings.preprocessing_flag = 1;
			}
		}else if ((start_pos = contents.find("no", tmp_pos)) != string::npos){
			if (start_pos < end_pos){
				settings.preprocessing_flag = 0;
			}
		}else{
//			settings.preprocessing_flag = PAR-DEF;
		}
	}else{
//		settings.preprocessing_flag = PAR-DEF;
	}
	// set true detection match version and selector
	if ((start_pos = contents.find(SETTINGS_OPTION[6])) != string::npos){
		tmp_pos = start_pos;
		end_pos = contents.find("\n", start_pos);
		if ((start_pos = contents.find("any", start_pos)) != string::npos){
			if (start_pos < end_pos){
				settings.true_detection_match = TDM_ANY;
			}
		}else if ((start_pos = contents.find("exact", tmp_pos)) != string::npos){
			if (start_pos < end_pos){
				settings.true_detection_match = TDM_EXACT;
			}
		}else{
//			settings.true_detection_match = PAR-DEF;
		}
	}else{
//		settings.true_detection_match = PAR-DEF;
	}
	if ((start_pos = contents.find(SETTINGS_OPTION[7])) != string::npos){
		end_pos = contents.find("\n", start_pos);
		string_format.str("");
		string_format.clear();
		string_format << SETTINGS_OPTION[7] << "%u";
		sscanf(contents.substr(start_pos, end_pos - start_pos).c_str(),
				 string_format.str().c_str(), &settings.true_detection_selector);
	}else{
//		settings.true_detection_selector = PAR-DEF;
	}

	return 0;
}

void finalize_settings(pca_basic_settings_t &settings){
	delete [] settings.selected_agreg_units;
}

/*TMP implementation - time continuity is not checked yet*/
int timeslot_is_continuous(uint64_t timeslot_num,uint64_t actual_timeslot_num, pca_basic_settings_t &settings){
	return 1;
}

int main(int argc, char **argv)
{
	// **************************************************************************
	// ***** DECLARATIONS *******************************************************
	#ifdef LOG_TO_FILE
	ofstream log;
	log.open(LOG_TO_FILE);
	if (!log.is_open()){
		cerr << "ERROR while opening log file <" << LOG_TO_FILE << ">\n" << flush;
	}
	#endif
	ofstream detection_log;

   int ret;
   trap_ifc_spec_t ifc_spec;

	pca_basic_settings_t settings;

	uint8_t timebin_init_flag = 1;
   unsigned int timebin_counter = 0;
   unsigned int round_timebin_counter = 0;
   uint64_t actual_timeslot_num;
   uint64_t timeslot_num;
   uint64_t *rcv_checker;
   uint64_t all_link_flag;
   uint64_t link_bit_field;
   unsigned int link_index;
   unsigned int write_col_selector;

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
   unsigned int normal_subspace_size;
   float **lin_op_c_residual;
   float **residual_traffic;
   uint8_t compute_residual_traffic_matrix = 1;

	float stdev; /*del-mark*/
	float *stdevs;

	#ifdef SPE_TESTING
   float phi [3];
   float lambda, SPE, h0, delta_SPE;
   uint8_t anomaly_detetected;
   #endif //SPE_TESTING

	#ifdef MULTI_TEST
	uint32_t anomaly_counter[NSS_DEF_CNT];
	for (int i = 0; i < NSS_DEF_CNT; i++){
		anomaly_counter[i] = 0;
	}

   unsigned int nss[NSS_DEF_CNT];
   unsigned int **anomaly_identification_fields;
   uint64_t anomaly_flag_field;
   unsigned int real_anomaly;

   ostringstream output_line, real_anom_output_line;
	ofstream anomaly_log ("multi-test_anomaly_log.txt");
	anomaly_log << endl;
   anomaly_log.close();
   ofstream real_anomaly_log ("multi-test_REAL_anomaly_log.txt");
	real_anomaly_log << endl;
   real_anomaly_log.close();
	#else//MULTI_TEST
	uint8_t anomaly_detected_flag = 0;
	uint32_t anomaly_counter = 0;
	detection_log.open("single-test_detection_log.txt");
	#endif//MULTI_TEST

	ofstream detection_log_values ;
	#ifdef VALUES
	detection_log_values.open("anomaly-detection-values-log.txt");
	#endif
   unsigned int *preprocessing_identification_field;

	// **************************************************************************
	// **************************************************************************
	// ***** PARSING PARAMETERS & INIT SETTINGS *********************************
   ret = trap_parse_params(&argc, argv, &ifc_spec);
   if (ret != TRAP_E_OK) {
      if (ret == TRAP_E_HELP) { // "-h" was found
         trap_print_help(&module_info);
         return 0;
      }
      cerr << "ERROR in parsing of parameters for TRAP: " << trap_last_error_msg << endl;
      return 1;
   }

   ret = init_settings (argc, argv, settings);
	if(ret){
		cerr << "Error while initializing module:\n\t" << error_msg_buffer.str() << endl;
		return ret;
	}

///* SETTINGS CHECK
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
	cout << "Expected timeslot increment is " << settings.timeslot_increment << "  DEF=" << DEFAULT_TIMESLOT_INCREMENT;
	cout << " and module accepting " << settings.out_of_timebin_rcv_tolerance << " front-deviation.\n";
	cout << "Preprocessing is ";
	if(settings.preprocessing_flag){
		cout << "ON.\n";
	}else{
		cout << "OFF.\n";
	}
	cout << "True detection mode is ";
	if(settings.true_detection_match == TDM_ANY){
		cout << "ANY-match.\n";
	}else if(settings.true_detection_match == TDM_EXACT){
		cout << "EXACT-match.\n";
	}else{
		cout << "wrong.\n";
	}
//	uint64_t true_detection_selector;//used by detector only
//	return 0;
//*/
	// **************************************************************************
	// **************************************************************************
	// ***** TRAP ININTIALIZATION ***********************************************

   // Create and init all interfaces
   ret = trap_init(&module_info, ifc_spec);
   if (ret != TRAP_E_OK) {
      cerr << "ERROR in TRAP initialization: " << trap_last_error_msg << endl;
      return 2;
   }

   trap_ifcctl(TRAPIFC_OUTPUT, 0, TRAPCTL_BUFFERSWITCH, 0); //turn off an output buffer

   // We don't need ifc_spec anymore, destroy it
   trap_free_ifc_spec(ifc_spec);
   // **************************************************************************
   // **************************************************************************
   // Register signal handler.
   TRAP_REGISTER_DEFAULT_SIGNAL_HANDLER();
   // **************************************************************************
   // **************************************************************************
   // ***** Create UniRec templates & allocate memory for output records *****
   ur_template_t *in_tmplt = ur_create_template(settings.in_unirec_specifier);

   ur_template_t *out_tmplt = ur_create_template(settings.out_unirec_specifier);

   void *out_rec = ur_create(out_tmplt, 0);
   // **************************************************************************
   // **************************************************************************
	// ***** MEMORY ALLOCAION AND INITIALIZATION ********************************
	rcv_checker = new uint64_t [settings.out_of_timebin_rcv_tolerance];
	for (int i = 0; i < settings.out_of_timebin_rcv_tolerance; i++){
		rcv_checker[i] = 0;
	}

	all_link_flag = 1;
	for (int i = 0; i < settings.link_count; i++){//2^link_count
		all_link_flag *= 2;
	}
	--all_link_flag;

	need_more_timebins = settings.working_timebin_window_size;

	raw_data_matrix = new float *[settings.working_timebin_window_size];
	for (int i = 0; i < settings.working_timebin_window_size; i++){
		raw_data_matrix[i] = new float [settings.data_matrix_width];
	}
	data_matrix.setlength(settings.working_timebin_window_size, settings.data_matrix_width);
	preprocessing_identification_field = new unsigned int [settings.data_matrix_width];
	for (int i = 0; i < settings.data_matrix_width; i++){
		preprocessing_identification_field[i] = 0;
	}
	principal_components.setlength(settings.data_matrix_width, settings.data_matrix_width);
	eigenvalues.setlength(settings.data_matrix_width);
	lin_op_c_residual = new float *[settings.data_matrix_width];
	for (int i = 0; i < settings.data_matrix_width; i++){
		lin_op_c_residual[i] = new float [settings.data_matrix_width];
	}
   residual_traffic = new float *[settings.working_timebin_window_size];
   for (int i = 0; i < settings.working_timebin_window_size; i++){
		residual_traffic[i] = new float [settings.data_matrix_width];
	}

	#ifdef NSS_BY_DELTA_TEST
   data2pc_projection = new float [settings.working_timebin_window_size];
   #endif//NSS_BY_DELTA_TEST

	#ifdef MULTI_TEST
	anomaly_identification_fields = new unsigned int *[DELTA_TESTNIG_CNT];
	if (anomaly_identification_fields == 0){
		cerr << "Mem err." << endl;
	}
   for (int i = 0; i < DELTA_TESTNIG_CNT; i++){
		anomaly_identification_fields[i] = new unsigned int [settings.data_matrix_width];
		for (int j = 0; j < settings.data_matrix_width; j++){
			anomaly_identification_fields[i][j] = 0;
		}
	}
	#endif//MULTI_TEST
   stdevs = new float [settings.data_matrix_width];


//	detection_log.open(ANOMALY_LOG_NAME);
//	detection_log<<"PCA-sketch anomaly detection log\n";
//	detection_log.close();
	///**************************************************************************
   ///**** TMP LOGING **********************************************************
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
	#endif//NSS_BY_DELTA_TEST

	detection_log << "\nDetect anomalies by " << DETECTION_TEST_CNT << " tests:\n";
	detection_log << "By new std DELTA-test for: ";
	for (int i = 0; i < DELTA_TESTNIG_CNT; i++){
		detection_log << DETECTION_THRESHOLD_MULTIPLIER(i) << "D ";
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
	///**************************************************************************
	///**************************************************************************
	///**************************************************************************
   // **************************************************************************
   // **************************************************************************
	// ***** MAIN PROCESSING LOOP ***********************************************
// ***** Main processing loop *****
   while (!stop) {
		// ***********************************************************************
		// ***** Get input data **************************************************
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
		// ***********************************************************************
		// ***** Process data ****************************************************
		if(timebin_init_flag){//Timeslot initialization with first received record
			actual_timeslot_num = ur_get(in_tmplt, in_rec, UR_TIME_FIRST);
			timebin_init_flag = 0;
		}

		// ***********************************************************************
		// ***** Timeslot continuity check ***************************************
		timeslot_num = ur_get(in_tmplt, in_rec, UR_TIME_FIRST);

		if (!timeslot_is_continuous(timeslot_num, actual_timeslot_num, settings)){/*TMP implementation of timeslot_is_continuous - time continuity is not checked yet*/
			cerr << "Received unexpected timebin number: " << timeslot_num << "(expected is: " << actual_timeslot_num
			<< " - " << actual_timeslot_num + (settings.out_of_timebin_rcv_tolerance * settings.timeslot_increment) << ")." << endl;
			stop = 1;
			break;
		}

//		if (rcv_checker[timebin_counter % settings.out_of_timebin_rcv_tolerance] == all_link_flag){//data for all links and one timebin was readed
		if (rcv_checker[0] == all_link_flag){//data for all links and one timebin was readed
			rcv_checker[0] = 0;
			actual_timeslot_num += DEFAULT_TIMESLOT_INCREMENT;
			round_timebin_counter = timebin_counter % settings.working_timebin_window_size;
			++timebin_counter;
			--need_more_timebins;
		}


		link_bit_field = ur_get(in_tmplt, in_rec, UR_LINK_BIT_FIELD);
		rcv_checker[0] |= link_bit_field;
		// ***********************************************************************
		// ***** Link identification ********************************************
		for (int i = 0; i < settings.link_count; i++){
			if ((link_bit_field >> i) & (uint64_t) 1){
				link_index = i;
				break;
			}
		}

		write_col_selector = 0;
		// ***********************************************************************
		// ***** Store data ******************************************************
		// if - order is important because of write_col_selector increment (agreg. units order in data matrix)
		if (settings.agreg_unit_field & MASK_BIT(AU_FLOWS)){
			raw_data_matrix[timebin_counter % settings.working_timebin_window_size][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_FLOWS);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_PACKETS)){
			raw_data_matrix[timebin_counter % settings.working_timebin_window_size][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_PACKETS);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_BYTES)){
			raw_data_matrix[timebin_counter % settings.working_timebin_window_size][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_BYTES);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_ESIP)){
			raw_data_matrix[timebin_counter % settings.working_timebin_window_size][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_ENTROPY_SRCIP);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_EDIP)){
			raw_data_matrix[timebin_counter % settings.working_timebin_window_size][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_ENTROPY_DSTIP);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_ESPORT)){
			raw_data_matrix[timebin_counter % settings.working_timebin_window_size][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_ENTROPY_SRCPORT);
			write_col_selector += settings.link_count;
		}
		if (settings.agreg_unit_field & MASK_BIT(AU_EDPORT)){
			raw_data_matrix[timebin_counter % settings.working_timebin_window_size][write_col_selector + link_index] = ur_get(in_tmplt, in_rec, UR_ENTROPY_DSTPORT);
			write_col_selector += settings.link_count;
		}

		// ***********************************************************************
		// ***** Detection core **************************************************
		if (!need_more_timebins){//data matrix is completed
			STATUS_MSG(LOG_DST,">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>\n")
			STATUS_MSG(LOG_DST,timebin_counter - 1 << ". timebin (" << round_timebin_counter << ") (timeslot " << timeslot_num << "): Data matrix is completed - starting detection...\n")

			++need_more_timebins;
			// ********************************************************************
			// ***** Matrix normalization - zero mean *****************************
			transform_matrix_zero_mean(raw_data_matrix,&data_matrix);
			// ********************************************************************
			// ***** Preprocess data **********************************************
			if (settings.preprocessing_flag){// !!! it's important to preprocess data here, since data matrix columns have zero mean
				STATUS_MSG(LOG_DST,"Preprocessing data..\n")
				ret = preprocess_data(&data_matrix, round_timebin_counter, preprocessing_identification_field);
				if (ret){
					cerr << error_msg_buffer.str() << endl;
					stop = 1;
					break;
				}
				#ifdef VALIDATION
				if(!(timebin_counter % settings.working_timebin_window_size) && timebin_counter){
							filename.str("");
							filename.clear();
							filename << "RAWx" << timebin_counter << "x" << round_timebin_counter;
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
							filename << "PRExRAWx" << timebin_counter << "x" << round_timebin_counter;
							ofs.open(filename.str().c_str());
							for (int i_val = 0; i_val < data_matrix.rows(); i_val++){
								for (int j_val = 0; j_val < data_matrix.cols(); j_val++){
									ofs << data_matrix(i_val,j_val) << "\t";
								}
								ofs << endl;
							}
							ofs.close();
				}
				#endif//VALIDATION
				if (preprocessing_identification_field){ //there is an anomaly(ies) from preprocessing
					detection_log << "From PREPROCESSING - in timebin " << timebin_counter - 1 << ": ";

					for (int i = 0; i < settings.data_matrix_width; i++){
						if (preprocessing_identification_field[i]){
							link_bit_field = 1 >> (i % settings.link_count);

							detection_log << i << "(" << settings.link_names[i % settings.link_count]
									<< "-au." << (i / settings.link_count) + 1 <<")\t \t";

							ur_set(out_tmplt, out_rec, UR_LINK_BIT_FIELD, link_bit_field);
							ur_set(out_tmplt, out_rec, UR_TIME_FIRST, timeslot_num);
							preprocessing_identification_field[i] = 0;
							ret = trap_send_data(0, out_rec, ur_rec_static_size(out_tmplt), TRAP_HALFWAIT);
							TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0, break);
						}
					}

					detection_log << endl;
				}
			}
			if (ret) break;
			// ********************************************************************
			// ***** Matrix normalization - unit energy ***************************
			for (int i = 0; i < settings.agreg_unit_per_link; i++){
				transform_submatrix_unit_energy(&data_matrix, settings.link_count * i, settings.link_count * (i + 1));
				if (ret){
					cerr << error_msg_buffer.str() << endl;
					stop = 1;
					break;
				}
			}
//			if (ret) break;
			// ********************************************************************
			// ***** Computing of PCA  ********************************************
			STATUS_MSG(LOG_DST,"\t  Computing PCA.\n")

			pcabuildbasis(data_matrix, settings.working_timebin_window_size, settings.data_matrix_width, info, eigenvalues, principal_components);
			if(info != 1){
				cerr << "Error while computing PCA (error code: " << info << ")" << endl << flush;
				stop = 1;
				break;
			}
///*******************************************************************************************************************************
///**::::: MULTI TESTING :::::::::::::::::::::::::::::::::::::::::::::::::::::::
			#ifdef MULTI_TEST
			{
			STATUS_MSG(LOG_DST,"\t  Starting MULTI-TEST.\n")

			detection_log.open("multi-test_detection_log.txt", ios::in | ios::app);
			detection_log << "----------------------------------------------------------------------------------------------" << endl;
			detection_log << timebin_counter << ".timebin (timeslot " << timeslot_num << ")" << endl;
			detection_log.close();
///******************************************************************************************************************
///***********************************************************************************************************
/// NSS DEFINITION ***********::::: MULTI TESTING :::::::::::::::::::::::::::::::::***************************
			STATUS_MSG(LOG_DST,"\t  Finding first 4 NSS ")

			for (int i = 0; i < 4; i++){// NSS by %
				sum_variance = 0;

				for (int j = 0; j < eigenvalues.length(); j++){
					sum_variance += eigenvalues(j);
				}
				variance_threshold = sum_variance * NSS_BY_PERCT_MULTIPLER(i);

				normal_subspace_size = eigenvalues.length();// data_matrices[i].cols() == eigenvalues.length() == data_matrix_width
				while(sum_variance >= variance_threshold){
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
					ret = multiply_matrix_column_vector(&data_matrix, &principal_components, wi, data2pc_projection);
					if (ret){
						cerr << error_msg_buffer.str() << endl;
						stop = 1;
						break;
					}
					norm = norm_of_vector(data2pc_projection, settings.working_timebin_window_size);
					divide_vector_by_value(data2pc_projection, settings.working_timebin_window_size, norm);
					delta_threshold = vector_standard_deviation_v2(data2pc_projection, settings.working_timebin_window_size);

					delta_threshold *= i - 1; // 3, 4, 5
					for (int k = 0; k < settings.working_timebin_window_size; k++){//"Delta" test
						if(data2pc_projection[k] >= delta_threshold || data2pc_projection[k] <= -delta_threshold){
							normal_subspace_size = wi;
						}
					}
					wi++;
				}
				if (ret) break;
				nss[i] = normal_subspace_size;
			}
			if (ret) break;
			#else//NSS_BY_DELTA_TEST
			STATUS_MSG(LOG_DST,"\n")
			#endif//NSS_BY_DELTA_TEST
/// END OF NSS DEFINITION ****::::: MULTI TESTING :::::::::::::::::::::::::::::::::**********************************
///***********************************************************************************************************
/// DETECTION ****************::::: MULTI TESTING :::::::::::::::::::::::::::::::::***************************

			STATUS_MSG(LOG_DST,"\t  Starting anomaly detection.\n")

			anomaly_log.open("multi-test_anomaly_log.txt", ios::in | ios::app);
			anomaly_log << "==================================================================================\n";
			anomaly_log << "Anomaly(ies) in timebin  " << timebin_counter << " (timeslot " << timeslot_num << ")" << endl;
			anomaly_log.close();

			real_anom_output_line.str("");
			real_anom_output_line.clear();
			real_anom_output_line << "==================================================================================\n";
			real_anom_output_line << "Anomaly(ies) in timebin " << timebin_counter << " (timeslot " << timeslot_num << ")" << endl;

			detection_log_values << "==================================================================================\n";
			detection_log_values << "Detection values in timebin " << timebin_counter << " (timeslot " << timeslot_num << ")" << endl;

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

				// ** Computing of linear operator C-residual (performs linear projection onto the anomaly subspace) **
				ret = multiply_submatrix_by_transposed_submatrix(&principal_components, nss[i], lin_op_c_residual);
				if (ret){
					cerr << error_msg_buffer.str() << endl;
					stop = 1;
					break;
				}
				substitute_from_identity_matrix(lin_op_c_residual, settings.data_matrix_width);
				// ** END OF Computing of linear operator C-residual ***

				for (int j = 0; j < settings.working_timebin_window_size; j++){
					ret = multiply_matrix_by_transposed_line(lin_op_c_residual, settings.data_matrix_width,
																		  &data_matrix, j, residual_traffic[j]);
				}
//				if (ret){
//					cerr << error_msg_buffer.str() << endl;
//					stop = 1;
//					break;
//				}
/// STDEV TESTING ************::::: MULTI TESTING :::::::::::::::::::::::::::::::::***************************
				STATUS_MSG(LOG_DST,"\t\t By std-dev testing...\n")

				for (int j = 0; j < settings.data_matrix_width; j++){
					stdevs[j] = vector_standard_deviation_v2(residual_traffic, settings.working_timebin_window_size, j);
				}

				detection_log_values << "\t\tSTD-DEV testing: " << endl;
/// ##################### 1. DETECTION CYCLE 0 - DELTA_TESTNIG_CNT ##############
				for (int k = 0; k < DELTA_TESTNIG_CNT; k++){
					for (int l = 0; l < settings.data_matrix_width; l++){

						detection_log_values << "\n\t\t  std-dev = " << stdevs[l] << endl;
						detection_log_values << "\t\t  values:  ";
						detection_log_values << residual_traffic[round_timebin_counter][l]  << "  ";

						if((residual_traffic[round_timebin_counter][l] > (stdevs[l] * DETECTION_THRESHOLD_MULTIPLIER(k))) ||
							(residual_traffic[round_timebin_counter][l] < -(stdevs[l] * DETECTION_THRESHOLD_MULTIPLIER(k)))){

							anomaly_flag_field |= MASK_BIT(k);
							anomaly_identification_fields[k][l] = 1;

							detection_log_values << "\t\t  for delta = " << DETECTION_THRESHOLD_MULTIPLIER(k)
														<< "(" << k << "): "<< l << ". anomalous value = " << residual_traffic[round_timebin_counter][l] << endl;
						}
					}
				}//for{} 1. detection cycle
/// END OF STDEV TESTING *****::::: MULTI TESTING :::::::::::::::::::::::::::::::::**********************************
				#ifdef SPE_TESTING
///SPE TESTING ***************::::: MULTI TESTING :::::::::::::::::::::::::::::::::***************************
				STATUS_MSG(LOG_DST,"\t\t By SPE testing...\n")

				SPE = norm_of_vector(residual_traffic[round_timebin_counter], settings.data_matrix_width);
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
/// ##################### 2. DETECTION CYCLE 0 - A_PERCENTILE_DEF_CNT ###################################################
				for (int k = 0; k < A_PERCENTILE_DEF_CNT; k++){
					delta_SPE = phi[0] * pow((
								((A_PERCENTILES[k] * sqrt(2.0 * phi[1] * h0 * h0)) / phi[0])
								+ 1.0 + ((phi[1] * h0 * (h0 - 1.0)) / (phi[0] * phi[0])) ),(1.0/h0));

					detection_log_values << "\t\t  " << k << ".[delta]-spe = " << delta_SPE << endl;
					if (SPE > delta_SPE){
						anomaly_flag_field |= MASK_BIT(k + DELTA_TESTNIG_CNT);// !!! DELTA_TESTNIG_CNT addition in anomaly_flag_field
					}
				}//for{} 2. detection cycle
/// END OF SPE TESTING *******::::: MULTI TESTING :::::::::::::::::::::::::::::::::**********************************
				#endif//SPE_TESTING

				real_anomaly = 0;

				if (anomaly_flag_field){
					++anomaly_counter[i];

					anomaly_log.open("multi-test_anomaly_log.txt", ios::in | ios::app);
					anomaly_log << "\tNSS variant " << i << endl;

					if (settings.true_detection_match == TDM_ANY){
						if (anomaly_flag_field & settings.true_detection_selector){real_anomaly = 1;}
					}else{//settings.true_detection_match == TDM_EXACT
						if (anomaly_flag_field >= settings.true_detection_selector){real_anomaly = 1;}
					}

					if (real_anomaly){
						real_anom_output_line << "\tNSS variant " << i << endl;
					}

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
										anomaly_log << l << "(" << settings.link_names[l % settings.link_count]
														<< "-au." << (l / settings.link_count) + 1 <<")";

										if(real_anomaly){
											link_bit_field = 1 >> (l % settings.link_count);
											ur_set(out_tmplt, out_rec, UR_LINK_BIT_FIELD, link_bit_field);
											ur_set(out_tmplt, out_rec, UR_TIME_FIRST, timeslot_num);

											real_anom_output_line << l << "(" << settings.link_names[l % settings.link_count]
																	<< "-au." << (l / settings.link_count) + 1 <<")";

											ret = trap_send_data(0, out_rec, ur_rec_static_size(out_tmplt), TRAP_HALFWAIT);
											TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0, break);
										}

										anomaly_identification_fields[j][l] = 0;
									}
								}
								anomaly_log << endl;
								if(real_anomaly){
									real_anom_output_line << endl;
								}
							}else{//no identification data is available
								ur_set(out_tmplt, out_rec, UR_LINK_BIT_FIELD, 0xffffffff);
								ur_set(out_tmplt, out_rec, UR_TIME_FIRST, timeslot_num);
								ret = trap_send_data(0, out_rec, ur_rec_static_size(out_tmplt), TRAP_HALFWAIT);
								TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0, break);
							}
						}else{
							output_line << "0 ";
						}
						if(!((j + 1) % 5)){
							output_line << " | ";
						}
					}//for{} anomaly vector iteration

					anomaly_log << "------------------------------------------------------------" << endl;
					anomaly_log.close();
					if(real_anomaly){
						real_anom_output_line << "------------------------------------------------------------" << endl;
					}
				}else{//if{} there is some anomaly
					output_line << "no anomaly";
				}//if-else{} - threre is NOT an anomaly

				detection_log.open("multi-test_detection_log.txt", ios::in | ios::app);
				detection_log << output_line.str() << endl;
				detection_log.close();

				if (real_anomaly){
					real_anomaly_log.open("multi-test_REAL_anomaly_log.txt", ios::in | ios::app);
					real_anomaly_log << real_anom_output_line.str();
					real_anom_output_line.str("");
					real_anom_output_line.clear();
					real_anomaly_log.close();
				}

				output_line.str("");
				output_line.clear();
			}//for{} every NSS definition
						}
/// END OF DETECTION *********::::: MULTI TESTING :::::::::::::::::::::::::::::::::**********************************
///******************************************************************************************************************
			#else //MULTI_TEST
///******************************************************************************************************************
///******************************************************************************************************************
///******************************************************************************************************************
///**,,,,, SINGLE TESTING ,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,*************************************
///******************************************************************************************************************
			STATUS_MSG(LOG_DST,"\t  Starting SINGLE-TEST.\n")

			detection_log << "----------------------------------------------------------------------------------------------" << endl;
			detection_log << timebin_counter - 1 << ".timebin (" << round_timebin_counter << ") (timeslot " << timeslot_num << ")" << endl;
///***********************************************************************************************************
/// NSS DEFINITION *********************,,,,, SINGLE TESTING ,,,,,,,,,,,,,,,,,,,,,,***************************
			// ********************************************************************
			// ***** Finding normal subspace size *********************************
			#ifdef NSS_FIXED
			normal_subspace_size = NSS_FIXED;
			#elif defined NSS_BY_PERCENTAGE
			sum_variance = 0;

			for (int j = 0; j < eigenvalues.length(); j++){//get total variance
				sum_variance += eigenvalues(j);
			}
			variance_threshold = sum_variance * NSS_BY_PERCENTAGE;//set threshold by % of total variance

			normal_subspace_size = eigenvalues.length();
			while(sum_variance > variance_threshold){//find first n principal componets according to xx% of total variance
				sum_variance -= eigenvalues(--normal_subspace_size);
			}
			normal_subspace_size++;//correction of last step
			#else// !NSS_FIXED && !NSS_BY_PERCENTAGE
			normal_subspace_size = 0;
			wi = 0;
			while (!normal_subspace_size && (wi < settings.data_matrix_width)){
				ret = multiply_matrix_column_vector(&data_matrix, &principal_components, wi, data2pc_projection);
				if (ret){
					cerr << error_msg_buffer.str() << endl;
					stop = 1;
					break;
				}
				norm = norm_of_vector(data2pc_projection, settings.working_timebin_window_size);
				divide_vector_by_value(data2pc_projection, settings.working_timebin_window_size, norm);
				delta_threshold = vector_standard_deviation_v2(data2pc_projection, settings.working_timebin_window_size);
				delta_threshold *= NSS_BY_DELTA_TEST;

				for (int k = 0; k < settings.working_timebin_window_size; k++){//"Delta" test
					if(data2pc_projection[k] >= delta_threshold || data2pc_projection[k] <= -delta_threshold){
						normal_subspace_size = wi;
					}
				}
				wi++;
			}
			if (ret) break;
			#endif//NSS definition
/// END OF NSS DEFINITION **************,,,,, SINGLE TESTING ,,,,,,,,,,,,,,,,,,,,,,**********************************
///***********************************************************************************************************
//			if(compute_residual_traffic_matrix){
//				for(int j = 0; j < settings.working_timebin_window_size){
//
//				}
//				compute_residual_traffic_matrix = 0;
//			}
///***********************************************************************************************************
/// DETECTION **************************,,,,, SINGLE TESTING ,,,,,,,,,,,,,,,,,,,,,,***************************

			STATUS_MSG(LOG_DST,"\t  Starting anomaly detection.\n")

			detection_log_values << "\n==================================================================================\n";
			detection_log_values << "Detection values in timebin " << timebin_counter - 1<< " (" << round_timebin_counter << ") (timeslot " << timeslot_num << ")" << endl;
			detection_log_values << "-----------------------------------------------------------------------------------\n";
			detection_log_values << "\tFor NSS-def ";
			#ifdef NSS_FIXED
			detection_log_values << "fixed";
			#elif defined NSS_BY_PERCENTAGE
			detection_log_values << NSS_BY_PERCENTAGE * 100 << "%";
			#else// !NSS_FIXED && !NSS_BY_PERCENTAGE
			detection_log_values << NSS_BY_DELTA_TEST << "D";
			#endif//NSS definition

			detection_log_values << " (NSS=" << normal_subspace_size << ")" << endl;
			detection_log << "   NSS=" << normal_subspace_size << "\t";
			// ********************************************************************
			// ***** Separate residual traffic ************************************
			// ** Computing of linear operator C-residual (performs linear projection onto the anomaly subspace) **
			ret = multiply_submatrix_by_transposed_submatrix(&principal_components, normal_subspace_size, lin_op_c_residual);
			if (ret){
				cerr << error_msg_buffer.str() << endl;
				stop = 1;
				break;
			}
			substitute_from_identity_matrix(lin_op_c_residual, settings.data_matrix_width);

//			ret = multiply_matrix_by_transposed_line(lin_op_c_residual, settings.data_matrix_width, &data_matrix,
//																  round_timebin_counter, residual_traffic[round_timebin_counter]);
//			if (ret){
//				cerr << error_msg_buffer.str() << endl;
//				stop = 1;
//				break;
//			}
			for (int j = 0; j < settings.working_timebin_window_size; j++){
				ret = multiply_matrix_by_transposed_line(lin_op_c_residual, settings.data_matrix_width,
																	  &data_matrix, j, residual_traffic[j]);
			}
			#ifdef VALIDATION
			if(!(timebin_counter % settings.working_timebin_window_size) && timebin_counter){
				filename.str("");
				filename.clear();
				if(settings.preprocessing_flag) filename << "PREx";
				filename << "DMx" << timebin_counter << "x" << round_timebin_counter;
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
				if(settings.preprocessing_flag) filename << "PREx";
				filename << "RES" << normal_subspace_size << "x" << timebin_counter << "x" << round_timebin_counter;
				ofs.open(filename.str().c_str());
				for (int i_val = 0; i_val < data_matrix.rows(); i_val++){
					for (int j_val = 0; j_val < data_matrix.cols(); j_val++){
						ofs << residual_traffic[i_val][j_val] << "\t";
					}
					ofs << endl;
				}
				ofs.close();
//				cin >> need_more_timebins;
			}
			#endif//VALIDATION
			// ********************************************************************
			// ***** Detection test ***********************************************
			#ifdef SPE_TESTING
///SPE TESTING *************************,,,,, SINGLE TESTING ,,,,,,,,,,,,,,,,,,,,,,***************************
			STATUS_MSG(LOG_DST,"\t\t By SPE testing....\n")

			SPE = norm_of_vector(residual_traffic[round_timebin_counter], settings.data_matrix_width);
			SPE *= SPE;

			detection_log_values << "\t\tSPE-testing: ";

			// ** Detecting anomalies by "SPE" test **
			phi[0] = 0;
			phi[1] = 0;
			phi[2] = 0;

			for (int j = normal_subspace_size; j < settings.data_matrix_width; j++){
				lambda = eigenvalues(j);
				phi[0] += lambda;
				lambda *= lambda;
				phi[1] += lambda;
				lambda *= lambda;
				phi[2] += lambda;
			}
			h0 = 1.0 - ((2.0 * phi[0] * phi[2]) / (3.0 * phi[1] * phi[1]));
			delta_SPE = phi[0] * pow((
							((A_PERCENTILES[SPE_TESTING] * sqrt(2.0 * phi[1] * h0 * h0)) / phi[0])
							+ 1.0 + ((phi[1] * h0 * (h0 - 1.0)) / (phi[0] * phi[0])) ),(1.0/h0));

			detection_log_values << "\t  SPE = " << SPE << "  ? > ?  DELTE_spe = " << delta_SPE << endl;

			if (SPE > delta_SPE){
				STATUS_MSG(LOG_DST,"\t\t  There is an ANOMALY.\n")
				++anomaly_counter;

				detection_log << "ANOMALY by SPE (alpha=" << A_PERCENTILES[SPE_TESTING] << ")" << endl;
				ur_set(out_tmplt, out_rec, UR_LINK_BIT_FIELD, 0xffffffff);
				ur_set(out_tmplt, out_rec, UR_TIME_FIRST, timeslot_num);
				ret = trap_send_data(0, out_rec, ur_rec_static_size(out_tmplt), TRAP_HALFWAIT);
				TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0, break);
			}else{
				STATUS_MSG(LOG_DST,"\t\t  No anomaly...\n")
			}
/// END OF SPE TESTING *****************,,,,, SINGLE TESTING ,,,,,,,,,,,,,,,,,,,,,,**********************************
			#else
/// STDEV TESTING **********************,,,,, SINGLE TESTING ,,,,,,,,,,,,,,,,,,,,,,***************************
			STATUS_MSG(LOG_DST,"\t\t By std-dev testing...\n")
//			cout << "tb: " << timebin_counter << endl;
			for (int j = 0; j < settings.data_matrix_width; j++){
				stdevs[j] = vector_standard_deviation_v2(residual_traffic, settings.working_timebin_window_size, j);
			}
			detection_log_values << "\t\tSTD-DEV testing: ";

			anomaly_detected_flag = 0;
			for (int j = 0; j < settings.data_matrix_width; j++){
				detection_log_values << "\n\t\t  std-dev = " << stdevs[j] << endl;
				detection_log_values << "\t\t  values:  ";
				detection_log_values << residual_traffic[round_timebin_counter][j]  << "  ";
				if((residual_traffic[round_timebin_counter][j] > (stdevs[j] * DEFAULT_DETECTION_THRESHOLD)) ||
					(residual_traffic[round_timebin_counter][j] < -(stdevs[j] * DEFAULT_DETECTION_THRESHOLD))){

					++anomaly_counter;

					anomaly_detected_flag = 1;

					detection_log << j << "(" << settings.link_names[j % settings.link_count]
									<< "-au." << (j / settings.link_count) + 1 <<")\t \t";

					detection_log_values << "   ANOMALOUS ";

					STATUS_MSG(LOG_DST,"\t\t  There is an ANOMALY on link " << settings.link_names[j % settings.link_count] << " (au-" << (j / settings.link_count) + 1 << ")")
					link_bit_field = 0 & MASK_BIT(j % settings.link_count);
					ur_set(out_tmplt, out_rec, UR_LINK_BIT_FIELD, link_bit_field);
					ur_set(out_tmplt, out_rec, UR_TIME_FIRST, timeslot_num);
					ret = trap_send_data(0, out_rec, ur_rec_static_size(out_tmplt), TRAP_HALFWAIT);
					TRAP_DEFAULT_SEND_DATA_ERROR_HANDLING(ret, 0, break);
				}
			}
			if (anomaly_detected_flag){
				detection_log << "      ANOMALY "<< endl;
			}else{
				detection_log << endl;
				STATUS_MSG(LOG_DST,"\t\t  No anomaly...\n")
			}
/// END OF STDEV TESTING ***************,,,,, SINGLE TESTING ,,,,,,,,,,,,,,,,,,,,,,**********************************
			#endif
/// END OF DETECTION *******************,,,,, SINGLE TESTING ,,,,,,,,,,,,,,,,,,,,,,**********************************
///******************************************************************************************************************
		#endif //else MULTI_TEST
		}//if{} DO NOT need_more_timebins
   }//<while>
   #ifdef MULTI_TEST
   detection_log_values.close();

   for (int i = 0; i < NSS_DEF_CNT; i++){
		STATUS_MSG(LOG_DST,"For " << i << ".NSS definition: " << anomaly_counter[i] << " anomaly found.\n")
   }
   #else//MULTI_TEST
	STATUS_MSG(LOG_DST, anomaly_counter << " anomaly found.\n")
	detection_log.close();
	#endif//MULTI_TEST
   // **************************************************************************
	// ***** CLEANUP ************************************************************
   #ifdef LOG_TO_FILE
	log.close();
	#endif//LOG_TO_FILE

	delete [] rcv_checker;

	for (int i = 0; i < settings.working_timebin_window_size; i++){
		delete [] raw_data_matrix[i];
	}
   delete [] raw_data_matrix;

	delete [] preprocessing_identification_field;

	#ifdef NSS_BY_DELTA_TEST
   delete [] data2pc_projection;
   #endif//NSS_BY_DELTA_TEST

   for (int i = 0; i < settings.data_matrix_width; i++){
		delete [] lin_op_c_residual[i];
	}
   delete [] lin_op_c_residual;

   for (int i = 0; i < settings.working_timebin_window_size; i++){
		delete [] residual_traffic[i];
	}
   delete [] residual_traffic;

   #ifdef MULTI_TEST
	for (int i = 0; i < DELTA_TESTNIG_CNT; i++){
   	delete [] anomaly_identification_fields[i];
   }
   delete [] anomaly_identification_fields;
	#endif//MULTI_TEST

   finalize_settings(settings);

   ur_free(out_rec);
   ur_free_template(out_tmplt);

   // Do all necessary cleanup before exiting
   TRAP_DEFAULT_FINALIZATION();

   ur_free_template(in_tmplt);
   // ***** END OF Cleanup *****

   return 0;

}
// END OF PCA_basic_detector.cpp
