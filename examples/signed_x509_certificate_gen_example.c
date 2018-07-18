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

int main() {
    uecm_x509_certificate *ca_certificate, *read_ca_certificate, *certificate;
    uecm_private_key *ca_private_key, *read_ca_private_key, *private_key;

    ca_certificate = NULL;
    ca_private_key = NULL;
    read_ca_certificate = NULL;
    read_ca_private_key = NULL;
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

    if (!uecm_x509_certificate_generate_self_signed_ca("SWA", &ca_certificate, &ca_private_key)) {
        ei_logger_error("Failed to generate self signed CA");
        goto clean_up;
    }

    if (!uecm_x509_certificate_print_pair(ca_certificate, ca_private_key, "out/ca_cert.pem", "out/ca_key.pem", NULL)) {
        ei_logger_error("Failed to print ca certificate and private key to files");
        goto clean_up;
    }

    if (!uecm_x509_certificate_load_from_files("out/ca_cert.pem", "out/ca_key.pem", NULL, &read_ca_certificate, &read_ca_private_key)) {
        ei_logger_error("Failed to load ca certificate and private from files");
        goto clean_up;
    }

    if (!uecm_x509_certificate_generate_signed(read_ca_certificate, read_ca_private_key, "SWA", &certificate, &private_key)) {
        ei_logger_error("Failed to generate certificate signed by CA");
        goto clean_up;
    }

    if (!uecm_x509_certificate_print_pair(ca_certificate, ca_private_key, "out/cert.pem", "out/key.pem", NULL)) {
        ei_logger_error("Failed to print signed certificate and private key to files");
        goto clean_up;
    }

	ei_logger_info("Succeed");

clean_up:
	if (ei_stacktrace_is_filled()) {
		ei_logger_error("Error(s) occurred with the following stacktrace(s) :");
		ei_stacktrace_print_all();
	}
    uecm_x509_certificate_destroy(ca_certificate);
    uecm_private_key_destroy(ca_private_key);
    uecm_x509_certificate_destroy(read_ca_certificate);
    uecm_private_key_destroy(read_ca_private_key);
    uecm_x509_certificate_destroy(certificate);
    uecm_private_key_destroy(private_key);
    uecm_uninit();
	ei_uninit();
    return 0;
}
