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
 *  @file      string_utility.h
 *  @brief     Utility functions for string manipulations.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_STRING_UTILITY_H
#define UNKNOWNECHOCRYPTOMODULE_STRING_UTILITY_H

#include <uecm/bool.h>

#include <stdarg.h>
#include <stddef.h>
#include <stdio.h>

void uecm_remove_last_char(char *str);

bool uecm_last_char_is(char *str, char c);

char *uecm_strcat_variadic(const char *format, ...);

int uecm_find_str_in_data(char *data, const char *query);

char *uecm_get_file_name_from_path(char *path);

char *uecm_get_file_extension(char *path);

char *uecm_string_create_from(const char *str);

char *uecm_string_create_from_bytes(unsigned char *bytes, size_t size);

char *uecm_append_dump_string(char *data, size_t max);

bool uecm_starts_with(const char *pre, const char *str);

int uecm_last_index_of(const char *string, char target);

char *uecm_string_reverse(char *string);

bool uecm_int_to_string(int num, char *buffer, int radix);

bool uecm_long_to_string(long num, char *buffer, int radix);

/**
 * Convert char * string to int out.
 * @param[in] string Input string to be converted.
 *
 * The format is the same as strtol,
 * except that the following are inconvertible:
 * - empty string
 * - leading whitespace
 * - any trailing characters that are not part of the number
 *   cannot be NULL.
 *
 * @param[out] out The converted int. Cannot be NULL.
 * @param[in] radix Base to interpret string in. Same range as strtol (2 to 36).
 * @return Indicates if the operation succeeded, or why it failed.
 */
bool uecm_string_to_int(char *string, int *out, int radix);

bool uecm_string_to_long(char *string, long *out, int radix);

int uecm_digit(char c, int radix);

/**
 * Returns a string that is a uecm_substring of this string. The
 * uecm_substring begins at the specified {@code begin_index} and
 * extends to the character at index {@code end_index - 1}.
 * Thus the length of the uecm_substring is {@code end_index-begin_index}.
 *
 * Examples:
 * "hamburger".uecm_substring(4, 8) returns "urge"
 * "smiles".uecm_substring(1, 5) returns "mile"
 *
 * @param      begin_index   the beginning index, inclusive.
 * @param      end_index     the ending index, exclusive.
 * @return     the specified uecm_substring.
 */
char *uecm_substring(char *string, int begin_index, int end_index);

char *uecm_get_until_symbol(char *str, int begin, char symbol, int *end);

char *uecm_trim_whitespace(char *str);

char *uecm_string_uppercase(const char *input);

#endif
