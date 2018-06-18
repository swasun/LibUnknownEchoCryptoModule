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

#include <uecm/crypto/api/key/sym_key.h>
#include <uecm/alloc.h>
#include <uecm/byte/byte_utility.h>
#include <uecm/string/string_utility.h>
#include <ei/ei.h>

#define SYM_KEY_MIN_SIZE 32

uecm_sym_key *uecm_sym_key_create(unsigned char *data, size_t size) {
	uecm_sym_key *key;

	ei_check_parameter_or_return(data);
	ei_check_parameter_or_return(size);

	if (size < SYM_KEY_MIN_SIZE) {
		ei_stacktrace_push_msg("Key size is too short. >= %d is required", SYM_KEY_MIN_SIZE);
		return NULL;
	}

	uecm_safe_alloc(key, uecm_sym_key, 1);
	key->data = uecm_bytes_create_from_bytes(data, size);
	key->size = size;

	return key;
}

void uecm_sym_key_destroy(uecm_sym_key *key) {
	if (key) {
		uecm_safe_free(key->data);
		uecm_safe_free(key);
	}
}

size_t uecm_sym_key_get_min_size() {
	return SYM_KEY_MIN_SIZE;
}

bool uecm_sym_key_is_valid(uecm_sym_key *key) {
	ei_check_parameter_or_return(key);
	ei_check_parameter_or_return(key->data);

	if (key->size < SYM_KEY_MIN_SIZE) {
		ei_stacktrace_push_msg("Key size is too short. >= %d is required", SYM_KEY_MIN_SIZE);
		return false;
	}

	return true;
}
