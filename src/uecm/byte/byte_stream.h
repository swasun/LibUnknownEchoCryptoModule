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
 *  @file      byte_stream.h
 *  @brief     Byte stream base functions, to alloc/desalloc stream, and get/set fields.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       byte_stream_struct.h
 *  @see       byte_reader.h
 *  @see       byte_writer.h
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_BYTE_STREAM_H
#define UNKNOWNECHOCRYPTOMODULE_BYTE_STREAM_H

#include <uecm/byte/byte_stream_struct.h>
#include <uecm/bool.h>

#include <stddef.h>
#include <stdio.h>

uecm_byte_stream *uecm_byte_stream_create();

uecm_byte_stream *uecm_byte_stream_create_size(size_t limit);

void uecm_byte_stream_clean_up(uecm_byte_stream *stream);

void uecm_byte_stream_destroy(uecm_byte_stream *stream);

unsigned char *uecm_byte_stream_get_data(uecm_byte_stream *stream);

size_t uecm_byte_stream_get_position(uecm_byte_stream *stream);

bool uecm_byte_stream_set_position(uecm_byte_stream *stream, size_t position);

size_t uecm_byte_stream_get_size(uecm_byte_stream *stream);

bool uecm_byte_stream_is_empty(uecm_byte_stream *stream);

void uecm_byte_stream_print_hex(uecm_byte_stream *stream, FILE *fd);

void uecm_byte_stream_print_string(uecm_byte_stream *stream, FILE *fd);

uecm_byte_stream *uecm_byte_stream_copy(uecm_byte_stream *stream);

#endif
