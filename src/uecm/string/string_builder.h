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
 *  @file      string_builder.h
 *  @brief     A string builder is a stream of string use to concatenate easily
 *             several types into a single string.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_STRING_BUILDER_H
#define UNKNOWNECHOCRYPTOMODULE_STRING_BUILDER_H

#include <uecm/bool.h>

#include <stddef.h>

typedef struct {
    char *data;
    size_t max_size;
    size_t position;
} uecm_string_builder;

uecm_string_builder *uecm_string_builder_create();

uecm_string_builder *uecm_string_builder_create_size(size_t max_size);

bool uecm_string_builder_append(uecm_string_builder *s, char *data, size_t data_len);

bool uecm_string_builder_append_variadic(uecm_string_builder *s, const char *format, ...);

void uecm_string_builder_clean_up(uecm_string_builder *s);

void uecm_string_builder_destroy(uecm_string_builder *s);

char *uecm_string_builder_get_data(uecm_string_builder *s);

size_t uecm_string_builder_get_position(uecm_string_builder *s);

#endif
