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

#include <uecm/init.h>
#include <uecm/bool.h>
#include <uecm/crypto/api/key/public_key.h>
#include <uecm/crypto/api/key/private_key.h>
#include <uecm/crypto/api/key/asym_key.h>
#include <uecm/crypto/api/certificate/x509_certificate.h>
#include <uecm/crypto/api/cipher/data_cipher.h>
#include <uecm/crypto/factory/rsa_asym_key_factory.h>
#include <uecm/alloc.h>
#include <ei/ei.h>
#include <uecm/byte/byte_utility.h>

#include <stddef.h>
#include <string.h>
#include <stdio.h>

#define CIPHER_ID   1
#define DECIPHER_ID 2

void print_usage(char *name) {
    printf("%s <data> <public_key> <private_key>\n", name);
}

int main(int argc, char **argv) {
    unsigned char *plain_data, *cipher_data, *decipher_data;
    size_t plain_data_size, cipher_data_size, decipher_data_size/*, i*/;
    uecm_x509_certificate *certificate;
    uecm_public_key *public_key;
    uecm_private_key *private_key;
    uecm_asym_key *asym_key;

    cipher_data = NULL;
    plain_data = NULL;
    decipher_data = NULL;
    certificate = NULL;
    public_key = NULL;
    private_key = NULL;
    asym_key = NULL;

    if (argc != 4) {
        fprintf(stderr, "[FATAL] Three arguments are required.\n");
        print_usage(argv[0]);
        exit(EXIT_FAILURE);
    }

	ei_init();

	if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEcho");
		goto clean_up;
	}

    if ((plain_data = uecm_bytes_create_from_string(argv[1])) == NULL) {
        ei_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    plain_data_size = strlen(argv[1]);

    uecm_x509_certificate_load_from_file(argv[2], &certificate);

    public_key = uecm_rsa_public_key_from_x509_certificate(certificate);

    private_key = uecm_rsa_private_key_from_key_certificate(argv[3]);

    if (!uecm_cipher_plain_data(plain_data, plain_data_size, public_key, private_key, &cipher_data, &cipher_data_size, "aes-256-cbc", "sha256")) {
        ei_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

    if (!uecm_decipher_cipher_data(cipher_data, cipher_data_size, private_key, public_key, &decipher_data, &decipher_data_size,
        "aes-256-cbc", "sha256")) {

        ei_stacktrace_push_msg("Failed to decipher cipher data");
        goto clean_up;
    }

    if (plain_data_size == decipher_data_size && memcmp(decipher_data, plain_data, plain_data_size) == 0) {
        ei_logger_info("Plain data and decipher data match");
    } else {
        ei_logger_error("Plain data and decipher data doesn't match");
    }

clean_up:
    uecm_public_key_destroy(public_key);
    uecm_private_key_destroy(private_key);
    uecm_asym_key_destroy_all(asym_key);
    uecm_safe_free(plain_data);
    uecm_safe_free(cipher_data);
    uecm_safe_free(decipher_data);
    uecm_x509_certificate_destroy(certificate);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ei_stacktrace_print_all();
    }
    uecm_uninit();
	ei_uninit();
    return 0;
}
