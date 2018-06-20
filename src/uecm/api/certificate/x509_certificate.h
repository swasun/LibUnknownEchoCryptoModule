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
 *  @file      x509_certificate.h
 *  @brief     Structure to represent an X509 certificate.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       https://en.wikipedia.org/wiki/X.509
 *  @todo      parsing : https://zakird.com/2013/10/13/certificate-parsing-with-openssl
 *  @todo      chain verification :
 *                - http://fm4dd.com/openssl/certverify.htm,
 *                - https://stackoverflow.com/questions/23407376/testing-x509-certificate-expiry-date-with-c
 *
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_H

#include <ueum/bool.h>
#include <uecm/api/key/private_key.h>

#include <stdio.h>
#include <stddef.h>

typedef struct uecm_x509_certificate uecm_x509_certificate;

uecm_x509_certificate *uecm_x509_certificate_create_empty();

bool uecm_x509_certificate_load_from_file(const char *file_name, uecm_x509_certificate **certificate);

bool uecm_x509_certificate_load_from_files(const char *cert_file_name, const char *key_file_name, const char *password, uecm_x509_certificate **certificate, uecm_private_key **private_key);

uecm_x509_certificate *uecm_x509_certificate_load_from_bytes(unsigned char *data, size_t data_size);

void uecm_x509_certificate_destroy(uecm_x509_certificate *certificate);

void *uecm_x509_certificate_get_impl(uecm_x509_certificate *certificate);

bool uecm_x509_certificate_set_impl(uecm_x509_certificate *certificate, void *impl);

bool uecm_x509_certificate_equals(uecm_x509_certificate *c1, uecm_x509_certificate *c2);

bool uecm_x509_certificate_print(uecm_x509_certificate *certificate, FILE *out_fd);

char *uecm_x509_certificate_to_pem_string(uecm_x509_certificate *certificate, size_t *result_size);

#endif
