/******************************************************************************************
 * Copyright (C) 2018 by Charly Lamothe                                                   *
 *                                                                                        *
 * This file is part of LibUnknownEchoCryptoModule.                                       *
 *                                                                                        *
 *   LibUnknownEchoCryptoModule is free software: you can redistribute it and/or modify   *
 *   it under the terms of the GNU General Public License as published by                 *
 *   the Free Software Foundation, either version 3 of the License, or                    *
 *   (at your option) any later version.                                                  *
 *                                                                                        *
 *   LibUnknownEchoCryptoModule is distributed in the hope that it will be useful,        *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of                       *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                        *
 *   GNU General Public License for more details.                                         *
 *                                                                                        *
 *   You should have received a copy of the GNU General Public License                    *
 *   along with LibUnknownEchoCryptoModule.  If not, see <http://www.gnu.org/licenses/>.  *
 ******************************************************************************************/

#include <uecm/uecm.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <stdio.h>

#define CERTIFICATE_PATH "out/cert.pem"
#define PRIVATE_KEY_PATH "out/key.pem"
#define CN               "SWA"

int main() {
    uecm_x509_certificate *certificate;
    uecm_private_key *private_key;

    certificate = NULL;
    private_key = NULL;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
        ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
        goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    ei_logger_debug("CERTIFICATE_PATH=%s", CERTIFICATE_PATH);
    ei_logger_debug("PRIVATE_KEY_PATH=%s", PRIVATE_KEY_PATH);
    ei_logger_debug("CN=%s", CN);

    ei_logger_info("Generating self signed x509 certificate and private key...");
    if (!uecm_x509_certificate_generate_self_signed_ca(CN, &certificate, &private_key)) {
        ei_logger_error("Failed to generate self signed CA");
        goto clean_up;
    }

    ei_logger_info("Writing to file self signed x509 certificate and private key...");
    if (!uecm_x509_certificate_print_pair(certificate, private_key, CERTIFICATE_PATH, PRIVATE_KEY_PATH, NULL)) {
        ei_logger_error("Failed to print ca certificate and private key to files");
        goto clean_up;
    }

    ei_logger_info("Succeed !");

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    uecm_x509_certificate_destroy(certificate);
    uecm_private_key_destroy(private_key);
    uecm_uninit();
    ei_uninit();
    return 0;
}
