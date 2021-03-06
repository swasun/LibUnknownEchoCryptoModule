/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

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
    uecm_signer *signer;
    unsigned char *signature, *message;
    size_t signature_length, message_length;
    uecm_asym_key *akey;

    exit_code = EXIT_FAILURE;
    signature = NULL;
    message = NULL;
    signer = NULL;
    akey = NULL;

    if (argc != 2) {
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
        ei_stacktrace_push_msg("Failed to convert arg to bytes");
        goto clean_up;
    }
    ei_logger_info("Succefully converted parameter to bytes");

    message_length = strlen(argv[1]);

    if ((akey = uecm_rsa_asym_key_create(2048)) == NULL) {
        ei_stacktrace_push_msg("Failed to create RSA key pair of 2048 bits");
        goto clean_up;
    }

    ei_logger_info("Creating RSA signer using the previous generated key pair...");
    if ((signer = uecm_rsa_signer_create_default_from_pair(akey)) == NULL) {
        ei_stacktrace_push_msg("Failed to create new RSA signer");
        goto clean_up;
    }

    ei_logger_info("Signing input message with RSA signer instance...");
    if (!uecm_signer_sign_buffer(signer, message, message_length, &signature, &signature_length)) {
        ei_stacktrace_push_msg("Failed to sign message");
        goto clean_up;
    }
    ei_logger_info("Message has been successfully signed");

    ei_logger_info("Verifying signature...");
    if ((uecm_signer_verify_buffer(signer, message, message_length, signature, signature_length))) {
        ei_logger_info("Signature matched with previous message");
    } else {
        ei_logger_error("Signature doesn't matched with previous message");
        ei_stacktrace_push_msg("Signature and buffer doesn't matched");
        goto clean_up;
    }

    ei_logger_info("Succeed !");

    exit_code = EXIT_SUCCESS;

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    ueum_safe_free(message);
    ueum_safe_free(signature);
    uecm_signer_destroy(signer);
    uecm_asym_key_destroy_all(akey);
    uecm_uninit();
    ei_uninit();
    return exit_code;
}
