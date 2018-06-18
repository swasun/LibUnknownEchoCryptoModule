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
 *  @file      string_vector.h
 *  @brief     A container that represent a vector of strings.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_STRING_VECTOR_H
#define UNKNOWNECHOCRYPTOMODULE_STRING_VECTOR_H

#include <uecm/bool.h>

#include <stdio.h>

typedef struct {
    char **elements;
    int number;
} uecm_string_vector;

uecm_string_vector *uecm_string_vector_create_empty();

void uecm_string_vector_clean_up(uecm_string_vector *v);

void uecm_string_vector_destroy(uecm_string_vector *v);

bool uecm_string_vector_append(uecm_string_vector *v, const char *new_string);

bool uecm_string_vector_append_vector(uecm_string_vector *from, uecm_string_vector *to);

bool uecm_string_vector_remove(uecm_string_vector *v, int index);

int uecm_string_vector_size(uecm_string_vector *v);

char *uecm_string_vector_get(uecm_string_vector *v, int index);

bool uecm_string_vector_is_empty(uecm_string_vector *v);

bool uecm_string_vector_print(uecm_string_vector *v, FILE *out);

bool uecm_string_vector_contains(uecm_string_vector *v, char *target);

#endif
