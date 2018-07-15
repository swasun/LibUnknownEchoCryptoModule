/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe													  *
 *																						  *
 * This file is part of LibUnknownEchoCryptoModule.										  *
 *																						  *
 *   LibUnknownEchoCryptoModule is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU General Public License as published by				  *
 *   the Free Software Foundation, either version 3 of the License, or					  *
 *   (at your option) any later version.												  *
 *																						  *
 *   LibUnknownEchoCryptoModule is distributed in the hope that it will be useful,        *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of						  *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the						  *
 *   GNU General Public License for more details.										  *
 *																						  *
 *   You should have received a copy of the GNU General Public License					  *
 *   along with LibUnknownEchoCryptoModule.  If not, see <http://www.gnu.org/licenses/>.  *
 ******************************************************************************************/

#ifndef UNKNOWNECHOCRYPTOMODULE_SYM_FILE_ENCRYPTION_H
#define UNKNOWNECHOCRYPTOMODULE_SYM_FILE_ENCRYPTION_H

#include <uecm/api/key/sym_key.h>
#include <ueum/ueum.h>

bool uecm_file_encrypt(const char *input_file_name, const char *output_file_name, uecm_sym_key *key, unsigned char **iv, size_t *iv_size);

bool uecm_file_decrypt(const char *input_file_name, const char *output_file_name, uecm_sym_key *key, unsigned char *iv);

#endif