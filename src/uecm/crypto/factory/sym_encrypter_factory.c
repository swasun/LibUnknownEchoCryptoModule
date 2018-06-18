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

#include <uecm/crypto/factory/sym_encrypter_factory.h>
#include <uecm/alloc.h>
#include <ei/ei.h>
#include <uecm/string/string_utility.h>
#include <uecm/defines.h>

static uecm_sym_encrypter *uecm_sym_encrypter_create_factory(uecm_sym_key *key, const char *cipher_name) {
	uecm_sym_encrypter *encrypter;

	if (!uecm_sym_key_is_valid(key)) {
		ei_stacktrace_push_msg("Specified key is invalid");
		return NULL;
	}

	if (key->size < uecm_sym_key_get_min_size()) {
		ei_stacktrace_push_msg("Specified key size is invalid. %d bytes is required.", uecm_sym_key_get_min_size());
		return NULL;
	}

	encrypter = uecm_sym_encrypter_create(cipher_name);
	uecm_sym_encrypter_set_key(encrypter, key);

	return encrypter;
}

uecm_sym_encrypter *uecm_sym_encrypter_aes_cbc_create(uecm_sym_key *key) {
	return uecm_sym_encrypter_create_factory(key, UNKNOWNECHOCRYPTOMODULE_DEFAULT_CIPHER_NAME);
}

uecm_sym_encrypter *uecm_sym_encrypter_rc4_create(uecm_sym_key *key) {
	return uecm_sym_encrypter_create_factory(key, "rc4");
}

uecm_sym_encrypter *uecm_sym_encrypter_default_create(uecm_sym_key *key) {
	return uecm_sym_encrypter_rc4_create(key);
}
