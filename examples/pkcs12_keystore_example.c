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
#include <uecm/alloc.h>
#include <ei/ei.h>
#include <uecm/crypto/api/keystore/pkcs12_keystore.h>

#include <stdio.h>

int main(int argc, char **argv) {
    uecm_pkcs12_keystore *keystore;

    if (argc != 3) {
        fprintf(stderr, "[ERROR] ./%s <file_path> <passphrase>\n", argv[0]);
        exit(1);
    }

	ei_init();

	if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEcho");
		goto clean_up;
	}

    if (!(keystore = uecm_pkcs12_keystore_load(argv[1], argv[2]))) {
        ei_stacktrace_push_msg("Failed to load specified pkcs12 keystore");
        goto clean_up;
    }

    if (!uecm_pkcs12_keystore_write(keystore, "out/keystore.p12", argv[2])) {
        ei_stacktrace_push_msg("Failed to write keystore to 'out/keystore.p12'");
        goto clean_up;
    }

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
