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

#include <uecm/uecm.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <stdlib.h>
#include <stddef.h>

int main(int argc, char **argv) {
    uecm_sym_key *key;
    unsigned char *iv;
    size_t iv_size;
    char *plain_file_name;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
		goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    key = NULL;
    iv = NULL;
    plain_file_name = NULL;

    ei_logger_info("Generating random key...");
    if ((key = uecm_sym_key_create_random()) == NULL) {
        ei_stacktrace_push_msg("Failed to create random sym key");
        goto clean_up;
    }
    ei_logger_info("Random key generated");

    ei_logger_info("Encrypting file %s...", argv[1]);
    if (!uecm_file_encrypt(argv[1], argv[2], key, &iv, &iv_size)) {
        ei_stacktrace_push_msg("Failed to encrypt file %s", argv[1]);
        goto clean_up;
    }
    ei_logger_info("File encrypted as file %s", argv[2]);

    plain_file_name = ueum_strcat_variadic("ss", "plain_", argv[1]);

    ei_logger_info("Decrypting file %s...", argv[2]);
    if (!uecm_file_decrypt(argv[2], plain_file_name, key, iv)) {
        ei_stacktrace_push_msg("Failed to decrypt file %s", argv[2]);
        goto clean_up;
    }
    ei_logger_info("File decrypted as file %s", plain_file_name);

	ei_logger_info("Succeed");

clean_up:
	if (ei_stacktrace_is_filled()) {
		ei_logger_error("Error(s) occurred with the following stacktrace(s) :");
		ei_stacktrace_print_all();
	}
    uecm_sym_key_destroy(key);
    ueum_safe_free(iv);
    ueum_safe_free(plain_file_name);
    uecm_uninit();
    ei_uninit();
    return 0;
}
