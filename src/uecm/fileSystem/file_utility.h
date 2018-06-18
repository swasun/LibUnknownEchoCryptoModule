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

/**
 *  @file      file_utility.h
 *  @brief     File system utils functions.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_FILE_UTILITY_H
#define UNKNOWNECHOCRYPTOMODULE_FILE_UTILITY_H

#include <stddef.h>
#include <stdio.h>

#include <uecm/bool.h>

bool uecm_is_file_exists(const char *file_name);

size_t uecm_get_file_size(FILE *fd);

char *uecm_read_file(const char *file_name);

bool uecm_write_file(const char *file_name, char *data);

unsigned char *uecm_read_binary_file(const char *file_name, size_t *size);

bool uecm_write_binary_file(const char *file_name, unsigned char *data, size_t size);

#endif
