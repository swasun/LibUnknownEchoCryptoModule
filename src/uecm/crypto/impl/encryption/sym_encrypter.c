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

#include <uecm/crypto/api/encryption/sym_encrypter.h>
#include <uecm/crypto/impl/errorHandling/openssl_error_handling.h>
#include <uecm/alloc.h>
#include <ei/ei.h>
#include <uecm/string/string_utility.h>

#include <openssl/evp.h>

struct uecm_sym_encrypter {
	uecm_sym_key *key;
	const EVP_CIPHER *cipher;
};

uecm_sym_encrypter *uecm_sym_encrypter_create(const char *cipher_name) {
	uecm_sym_encrypter *encrypter;
	char *error_buffer;

	uecm_safe_alloc(encrypter, uecm_sym_encrypter, 1);
	encrypter->key = NULL;
	if (!(encrypter->cipher = EVP_get_cipherbyname(cipher_name))) {
		uecm_openssl_error_handling(error_buffer, "Invalid cipher name");
		uecm_safe_free(encrypter);
		return NULL;
	}

	return encrypter;
}

void uecm_sym_encrypter_destroy(uecm_sym_encrypter *encrypter) {
	if (encrypter) {
		uecm_safe_free(encrypter);
	}
}

void uecm_sym_encrypter_destroy_all(uecm_sym_encrypter *encrypter) {
	if (encrypter) {
		uecm_sym_key_destroy(encrypter->key);
		uecm_safe_free(encrypter);
	}
}

uecm_sym_key *uecm_sym_encrypter_get_key(uecm_sym_encrypter *encrypter) {
	return encrypter->key;
}

bool uecm_sym_encrypter_set_key(uecm_sym_encrypter *encrypter, uecm_sym_key *key) {
	ei_check_parameter_or_return(encrypter);

	if (!uecm_sym_key_is_valid(key)) {
		ei_stacktrace_push_msg("Specified key is invalid");
		return false;
	}

	encrypter->key = key;

	return true;
}

size_t uecm_sym_encrypter_get_iv_size(uecm_sym_encrypter *encrypter) {
	return EVP_CIPHER_iv_length(encrypter->cipher);
}

bool uecm_sym_encrypter_encrypt(uecm_sym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size,
	unsigned char *iv, unsigned char **ciphertext, size_t *ciphertext_size) {

	int len, rlen;
	EVP_CIPHER_CTX *ctx;
	char *error_buffer;

	error_buffer = NULL;

	ei_check_parameter_or_return(encrypter);
	ei_check_parameter_or_return(plaintext);
	ei_check_parameter_or_return(iv);
	ei_check_parameter_or_return(plaintext_size);

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		uecm_openssl_error_handling(error_buffer, "EVP_CIPHER_CTX_new");
		return false;
	}

	if (EVP_EncryptInit_ex(ctx, encrypter->cipher, NULL, encrypter->key->data, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		uecm_openssl_error_handling(error_buffer, "EVP_EncryptInit_ex");
		return false;
	}

	uecm_safe_alloc(*ciphertext, unsigned char, plaintext_size + uecm_sym_encrypter_get_iv_size(encrypter));

	if (EVP_EncryptUpdate(ctx, *ciphertext, &len, plaintext, plaintext_size) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		uecm_openssl_error_handling(error_buffer, "EVP_EncryptUpdate");
		return false;
	}

	*ciphertext_size = len;

	if (EVP_EncryptFinal_ex(ctx, *ciphertext + len, &rlen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		uecm_openssl_error_handling(error_buffer, "EVP_EncryptFinal_ex");
		return false;
	}

	*ciphertext_size += rlen;

	EVP_CIPHER_CTX_free(ctx);

	return true;
}

bool uecm_sym_encrypter_decrypt(uecm_sym_encrypter *encrypter, unsigned char *ciphertext, size_t ciphertext_size,
	unsigned char *iv, unsigned char **plaintext, size_t *plaintext_size) {

	EVP_CIPHER_CTX *ctx;
	int len, rlen;
	char *error_buffer;

	error_buffer = NULL;

	if (!(ctx = EVP_CIPHER_CTX_new())) {
		uecm_openssl_error_handling(error_buffer, "EVP_CIPHER_CTX_new");
		return false;
	}

	if (EVP_DecryptInit_ex(ctx, encrypter->cipher, NULL, encrypter->key->data, iv) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		uecm_openssl_error_handling(error_buffer, "EVP_DecryptInit_ex");
		return false;
	}

	uecm_safe_alloc(*plaintext, unsigned char, ciphertext_size + uecm_sym_encrypter_get_iv_size(encrypter));

	if (EVP_DecryptUpdate(ctx, *plaintext, &len, ciphertext, ciphertext_size) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		uecm_openssl_error_handling(error_buffer, "EVP_DecryptUpdate");
		return false;
	}

	*plaintext_size = len;

	if (EVP_DecryptFinal_ex(ctx, *plaintext + len, &rlen) != 1) {
		EVP_CIPHER_CTX_free(ctx);
		uecm_openssl_error_handling(error_buffer, "EVP_DecryptFinal_ex");
		return false;
	}

	*plaintext_size += rlen;

	EVP_CIPHER_CTX_free(ctx);

	return true;
}
