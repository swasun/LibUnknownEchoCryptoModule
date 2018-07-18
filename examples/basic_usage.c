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

#include <uecm/uecm.h> /* Include LibUnknownEchoCryptoModule */
#include <ueum/ueum.h> /* Include LibUnknownEchoUtilsModule */
#include <ei/ei.h> /* Include LibErrorInterceptor */

#include <stddef.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned char *plain_data, *cipher_data, *decipher_data;
    size_t plain_data_size, cipher_data_size, decipher_data_size;
    uecm_asym_key *key;
    int key_size;

    /* Initialize LibErrorInterceptor */
    ei_init_or_die();
    ei_logger_use_symbol_levels();

    /* Initialize LibUnknownEchoCryptoModule */
    if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
		goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    /* Use LibUnknownEchoCryptoModule */

    plain_data = NULL;
    cipher_data = NULL;
    decipher_data = NULL;
    key_size = 4096;

    /* Convert the string input in bytes */
    ei_logger_info("Converting string input in bytes...");
    if ((plain_data = ueum_bytes_create_from_string(argv[1])) == NULL) {
        ei_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    plain_data_size = strlen(argv[1]);

    /* Generate a random RSA key pair */
    ei_logger_info("Generating random RSA key pair of size %d...", key_size);
    if ((key = uecm_rsa_asym_key_create(key_size)) == NULL) {
        ei_stacktrace_push_msg("Failed to generate random rsa key pair of size %d", key_size);
        goto clean_up;
    }
    
    /**
     * Cipher plain data using both asymmetric (4096-RSA) and
     * symmetric encryption (AES-256-CBC), compression
     * (inflate/deflate of zlib), signing (SHA-256).
     * The private key parameter (key->sk) is optional,
     * and used to sign the cipher data.
     */ 
    ei_logger_info("Ciphering plain data...");
    if (!uecm_cipher_plain_data(plain_data, plain_data_size, key->pk, key->sk, &cipher_data, &cipher_data_size, "aes-256-cbc", "sha256")) {
        ei_stacktrace_push_msg("Failed to cipher plain data");
        goto clean_up;
    }

    /**
     * Decipher cipher data using both asymmetric (4096-RSA) and
     * symmetric encryption (AES-256-CBC), compression
     * (inflate/deflate of zlib), signing (SHA-256).
     * The public key parameter (key->pk) is optional,
     * and used to verify the signature of the cipher data.
     */
    ei_logger_info("Deciphering cipher data...");
    if (!uecm_decipher_cipher_data(cipher_data, cipher_data_size, key->sk, key->pk, &decipher_data, &decipher_data_size,
        "aes-256-cbc", "sha256")) {

        ei_stacktrace_push_msg("Failed to decipher cipher data");
        goto clean_up;
    }

    /* Check if decipher data and plain data are equals */
    ei_logger_info("Comparing decipher data with plain data...");
    if (plain_data_size == decipher_data_size && memcmp(decipher_data, plain_data, plain_data_size) == 0) {
        ei_logger_info("Plain data and decipher data match");
    } else {
        ei_logger_error("Plain data and decipher data doesn't match");
    }

    ei_logger_info("Succeed !");

clean_up:
    /* Clean_up variables */
    ueum_safe_free(plain_data);
    ueum_safe_free(cipher_data);
    ueum_safe_free(decipher_data);
    uecm_asym_key_destroy_all(key);

    /**
     * Each time ei_stacktrace API is used in libueum or libuecm,
     * an error is record to the stacktrace of the current thread.
     */
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }

    uecm_uninit(); /* uninitialize LibUnknownEchoCryptoModule */

    ei_uninit(); /* uninitialize LibErrorInterceptor */

    return 0;
}
