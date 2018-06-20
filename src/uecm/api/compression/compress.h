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
 *  @file      compress.h
 *  @brief     Compress/decompress byte or file.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_COMPRESS_H
#define UNKNOWNECHOCRYPTOMODULE_COMPRESS_H

#include <ueum/bool.h>

#include <stddef.h>
#include <stdio.h>

unsigned char *uecm_compress_buf(unsigned char *plaintext, size_t plaintext_size, size_t *compressed_size);

unsigned char *uecm_decompress_buf(unsigned char *compressed_text, size_t compressed_text_size, size_t plaintext_size);

bool uecm_compress_file(FILE *source, FILE *dest);

bool uecm_decompress_file(FILE *source, FILE *dest);

#endif
