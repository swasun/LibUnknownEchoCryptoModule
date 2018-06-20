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

#include <uecm/factory/sym_key_factory.h>
#include <uecm/factory/hasher_factory.h>
#include <uecm/utils/crypto_random.h>
#include <uecm/api/hash/hasher.h>
#include <ei/ei.h>
#include <ueum/alloc.h>
#include <ueum/byte/byte_utility.h>

#include <stddef.h>
#include <string.h>

uecm_sym_key *uecm_sym_key_create_random() {
	uecm_sym_key *key;
	unsigned char *buf;
	size_t buf_size;

	key = NULL;
	buf_size = uecm_sym_key_get_min_size();
	ueum_safe_alloc(buf, unsigned char, buf_size);

	if (!uecm_crypto_random_bytes(buf, buf_size)) {
		ei_stacktrace_push_msg("Failed to get crypto random bytes");
		ueum_safe_free(buf);
		return NULL;
	}

	key = uecm_sym_key_create(buf, buf_size);

	ueum_safe_free(buf);

	return key;
}

uecm_sym_key *uecm_sym_key_create_from_file(char *file_path) {
	(void)file_path;
	ei_stacktrace_push_msg("Not implemented");
	return NULL;
}

uecm_sym_key *uecm_sym_key_create_from_string(const char *string) {
    uecm_sym_key *key;
    unsigned char *buf, *digest;
    uecm_hasher *hasher;
    size_t digest_len;

    hasher = uecm_hasher_default_create();

    buf = ueum_bytes_create_from_string(string);

    digest = uecm_hasher_digest(hasher, buf, strlen(string), &digest_len);

    key = uecm_sym_key_create(digest, digest_len);

    uecm_hasher_destroy(hasher);
    ueum_safe_free(buf);
    ueum_safe_free(digest);

    return key;
}
