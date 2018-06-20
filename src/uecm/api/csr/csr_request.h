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

#ifndef UNKNOWNECHOCRYPTOMODULE_CSR_REQUEST_H
#define UNKNOWNECHOCRYPTOMODULE_CSR_REQUEST_H

#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/key/private_key.h>
#include <uecm/api/key/public_key.h>
#include <uecm/api/key/sym_key.h>

#include <stddef.h>

unsigned char *uecm_csr_build_client_request(uecm_x509_certificate *certificate, uecm_private_key *private_key,
    uecm_public_key *ca_public_key, size_t *cipher_data_size, uecm_sym_key *future_key, unsigned char *iv, size_t iv_size,
    const char *cipher_name, const char *digest_name);

uecm_x509_certificate *uecm_csr_process_server_response(unsigned char *server_response, size_t server_response_size, uecm_sym_key *key,
    unsigned char *iv, size_t iv_size);

unsigned char *uecm_csr_build_server_response(uecm_private_key *csr_private_key, uecm_x509_certificate *ca_certificate, uecm_private_key *ca_private_key,
    unsigned char *client_request, size_t client_request_size, size_t *server_response_size, uecm_x509_certificate **signed_certificate,
    const char *cipher_name, const char *digest_name);

#endif
