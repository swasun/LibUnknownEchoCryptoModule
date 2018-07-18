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
#include <string.h>

static void print_usage(char *name) {
    printf("%s <data>\n", name);
}

int main(int argc, char **argv) {
    int exit_code;
    uecm_signer *s;
    unsigned char *signature, *message;
    size_t signature_length, message_length;
    uecm_asym_key *akey;

    exit_code = EXIT_FAILURE;
	signature = NULL;
	message = NULL;
    s = NULL;
    akey = NULL;

    if (argc == 1) {
        fprintf(stderr, "[FATAL] An argument is required.\n");
        print_usage(argv[0]);
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

    ei_logger_info("Converting parameter '%s' to bytes...", argv[1]);
    if ((message = ueum_bytes_create_from_string(argv[1])) == NULL) {
        ei_stacktrace_push_msg("Failed to convert arg to bytes")
        goto clean_up;
    }
    ei_logger_info("Succefully converted parameter to bytes");

    message_length = strlen(argv[1]);

    akey = uecm_rsa_asym_key_create(2048);

    ei_logger_info("Creating rsa uecm_signer with random asym key of 2048 bits...");
    if ((s = uecm_rsa_signer_create_default_from_pair(akey)) == NULL) {
        ei_stacktrace_push_msg("Failed to create rsa uecm_signer with random asym key")
        goto clean_up;
    }
    ei_logger_info("Rsa uecm_signer has been successfully created");

    ei_logger_info("Signing message with rsa uecm_signer instance...");
    if (!uecm_signer_sign_buffer(s, message, message_length, &signature, &signature_length)) {
        ei_stacktrace_push_msg("Failed to sign message")
        goto clean_up;
    }
    ei_logger_info("Message successfully signed");

    ei_logger_info("Verifying signature...");
    if ((uecm_signer_verify_buffer(s, message, message_length, signature, signature_length))) {
        ei_logger_info("Signature matched with previous message");
    } else {
        ei_logger_error("Signature doesn't matched with previous message");
        ei_stacktrace_push_msg("Signature and buffer doesn't matched")
        goto clean_up;
    }

    exit_code = EXIT_SUCCESS;

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    ueum_safe_free(message);
    ueum_safe_free(signature);
    uecm_signer_destroy(s);
    uecm_asym_key_destroy_all(akey);
    uecm_uninit();
	ei_uninit();
    return exit_code;
}
