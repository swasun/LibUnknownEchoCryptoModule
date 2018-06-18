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

/**
 *  @file      x509_csr.h
 *  @brief     Structure to represent an X509 CSR (Certificate Signing Request), in order
 *             to sign issuer certificate (like a client) by CA certificate (like a server).
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       https://en.wikipedia.org/wiki/Certificate_signing_request
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CSR_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CSR_H

#include <uecm/crypto/api/certificate/x509_certificate.h>
#include <uecm/crypto/api/key/private_key.h>
#include <uecm/bool.h>

#include <stdio.h>
#include <stddef.h>

typedef struct uecm_x509_csr uecm_x509_csr;

uecm_x509_csr *uecm_x509_csr_create(uecm_x509_certificate *certificate, uecm_private_key *private_key);

void uecm_x509_csr_destroy(uecm_x509_csr *csr);

bool uecm_x509_csr_print(uecm_x509_csr *csr, FILE *fd);

char *uecm_x509_csr_to_string(uecm_x509_csr *csr);

uecm_x509_csr *uecm_x509_string_to_csr(char *string);

uecm_x509_csr *uecm_x509_bytes_to_csr(unsigned char *data, size_t data_size);

uecm_x509_certificate *uecm_x509_csr_sign(uecm_x509_csr *csr, uecm_private_key *private_key);

void *uecm_x509_csr_get_impl(uecm_x509_csr *csr);

#endif
