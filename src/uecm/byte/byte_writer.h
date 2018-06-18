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
  *  @file      byte_writer.h
  *  @brief     Functions to append different data types into a byte stream.
  *  @author    Charly Lamothe
  *  @copyright GNU Public License.
  *  @see       byte_stream_struct.h
  *  @see       byte_stream.h
  *  @see       byte_reader.h
  */

#ifndef UNKNOWNECHOCRYPTOMODULE_BYTE_WRITER_H
#define UNKNOWNECHOCRYPTOMODULE_BYTE_WRITER_H

#include <uecm/bool.h>
#include <uecm/byte/byte_stream_struct.h>

#include <stddef.h>

bool uecm_byte_writer_append_bytes(uecm_byte_stream *stream, unsigned char *bytes, long bytes_len);

bool uecm_byte_writer_append_string(uecm_byte_stream *stream, const char *string);

bool uecm_byte_writer_append_byte(uecm_byte_stream *stream, unsigned char byte);

bool uecm_byte_writer_append_int(uecm_byte_stream *stream, int n);

bool uecm_byte_writer_append_long(uecm_byte_stream *stream, long n);

bool uecm_byte_writer_append_stream(uecm_byte_stream *stream, uecm_byte_stream *to_copy);

#endif
