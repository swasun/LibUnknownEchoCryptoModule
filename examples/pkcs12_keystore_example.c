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

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

int main(int argc, char **argv) {
    uecm_pkcs12_keystore *keystore;
    const char *keystore_path;

	keystore = NULL;
    keystore_path = "out/keystore.p12";

    if (argc != 2) {
        fprintf(stderr, "[ERROR] ./%s <passphrase>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

	ei_init_or_die();
    ei_logger_use_symbol_levels();

	ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
		goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    ei_logger_info("Checking if %s exist...", keystore_path);
    if (!ueum_is_file_exists(keystore_path)) {
        ei_logger_info("%s doesn't exist. Generating random pkcs12 keystore with CN=SWA and friendly name=test...", keystore_path);
        keystore = uecm_pkcs12_keystore_create_random("SWA", "test");
        if (!uecm_pkcs12_keystore_write(keystore, keystore_path, argv[1])) {
            ei_stacktrace_push_msg("Failed to write keystore to 'out/keystore.p12'");
            goto clean_up;
        }
    } else {
        ei_logger_info("Loading pkcs12 keystore %s...", keystore_path);
        if ((keystore = uecm_pkcs12_keystore_load(keystore_path, argv[1])) == NULL) {
            ei_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
            goto clean_up;
        }

        /**
         * Print the plain content of pkcs12 keystore on stdout.
         * Only for debugging purpose.
         */
        ei_logger_info("Print plain content of pkcs12 keystore %s to stdout...", keystore_path);
        if (!uecm_pkcs12_keystore_print(keystore, argv[1])) {
            ei_stacktrace_push_msg("Failed to print plain content keystore to stdout");
            goto clean_up;
        }

        ei_logger_info("Removing %s...", keystore_path);
        errno = 0;
        if (remove(keystore_path) != 0) {
            ei_stacktrace_push_msg("Failed to remove %s with error message: %s", keystore_path, strerror(errno));
            goto clean_up;
        }
    }

    ei_logger_info("Succeed !");

clean_up:
    uecm_pkcs12_keystore_destroy(keystore);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s) :");
        ei_stacktrace_print_all();
    }
    uecm_uninit();
	ei_uninit();
	return EXIT_SUCCESS;
}
