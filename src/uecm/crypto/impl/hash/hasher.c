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

#include <uecm/crypto/api/hash/hasher.h>
#include <uecm/crypto/impl/errorHandling/openssl_error_handling.h>
#include <uecm/alloc.h>
#include <ei/ei.h>
#include <uecm/string/string_utility.h>

#include <openssl/evp.h>
#include <openssl/sha.h>
#include <string.h>

struct uecm_hasher {
	EVP_MD_CTX *md_ctx;
	const EVP_MD *type;
};

uecm_hasher *uecm_hasher_create() {
	uecm_hasher *h;

	uecm_safe_alloc(h, uecm_hasher, 1);
	h->md_ctx = NULL;

	return h;
}

void uecm_hasher_destroy(uecm_hasher *h) {
	if (h) {
		EVP_MD_CTX_destroy(h->md_ctx);
		uecm_safe_free(h);
	}
}

bool uecm_hasher_init(uecm_hasher *h, const char *digest_name) {
	char *error_buffer;

	error_buffer = NULL;

	if ((h->md_ctx = EVP_MD_CTX_create()) == NULL) {
		uecm_openssl_error_handling(error_buffer, "Initialisation of message digest context");
		return false;
	}

    if (!(h->type = EVP_get_digestbyname(digest_name))) {
        uecm_openssl_error_handling(error_buffer, "Digest wasn't found");
        return false;
    }

	return true;
}

static unsigned char *build_digest(uecm_hasher *h, const unsigned char *message, size_t message_len, unsigned int *digest_len) {
	char *error_buffer;
	unsigned char *digest;

	error_buffer = NULL;
	digest = NULL;

	if (EVP_DigestInit_ex(h->md_ctx, h->type, NULL) != 1) {
		uecm_openssl_error_handling(error_buffer, "Initialisation of message digest function");
		return NULL;
	}

	if (EVP_DigestUpdate(h->md_ctx, message, message_len) != 1) {
		uecm_openssl_error_handling(error_buffer, "Digest update");
		return NULL;
	}

	if ((digest = (unsigned char *)OPENSSL_malloc(EVP_MD_size(h->type))) == NULL) {
		uecm_openssl_error_handling(error_buffer, "Allocation of digest string");
		return NULL;
	}

	if (EVP_DigestFinal_ex(h->md_ctx, digest, digest_len) != 1) {
		uecm_openssl_error_handling(error_buffer, "Digest final step");
		return NULL;
	}

	return digest;
}

unsigned char *uecm_hasher_digest(uecm_hasher *h, const unsigned char *message, size_t message_len, size_t *digest_len) {
	unsigned char *digest;
	unsigned int digest_len_tmp;

    if (!(digest = build_digest(h, message, message_len, &digest_len_tmp))) {
        ei_stacktrace_push_msg("Failed to build digest");
        return NULL;
    }
	*digest_len = (size_t)digest_len_tmp;

	return digest;
}

int uecm_hasher_get_digest_size(uecm_hasher *h) {
	return EVP_MD_size(h->type);
}
