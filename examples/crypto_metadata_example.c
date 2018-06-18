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
#include <ei/ei.h>
#include <uecm/crypto/api/crypto_metadata.h>
#include <uecm/crypto/factory/crypto_metadata_factory.h>

int main() {
    uecm_crypto_metadata *our_crypto_metadata, *read_crypto_metadata;

	ei_init();

	if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEcho");
		goto clean_up;
	}
    ei_logger_info("UnknownEchoLibCryptoModule is correctly initialized");

    our_crypto_metadata = NULL;
    read_crypto_metadata = uecm_crypto_metadata_create_empty();

    ei_logger_info("Generating crypto metadata for point A...");
    if (!(our_crypto_metadata = uecm_crypto_metadata_create_default())) {
        ei_stacktrace_push_msg("Failed to generate default crypto metadata for point A");
        goto clean_up;
    }

    ei_logger_info("Writing our crypto metadata...");
    if (!uecm_crypto_metadata_write(our_crypto_metadata, "out", "uid", "password")) {
        ei_stacktrace_push_msg("Failed to write our crypto metadata");
        goto clean_up;
    }
    ei_logger_info("Successfully wrote our crypto metadata");

    if (!uecm_crypto_metadata_read(read_crypto_metadata, "out", "uid", "password")) {
        ei_stacktrace_push_msg("Failed to read our crypto metadata");
        goto clean_up;
    }
    ei_logger_info("Successfully read our crypto metadata");

clean_up:
    uecm_crypto_metadata_destroy_all(our_crypto_metadata);
    uecm_crypto_metadata_destroy_all(read_crypto_metadata);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    uecm_uninit();
	ei_uninit();
    return 0;
}
