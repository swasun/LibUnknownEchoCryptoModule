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
 *  @file      pkcs12_keystore.h
 *  @brief     PKCS12 keystore structure.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @details   - Little description : https://en.wikipedia.org/wiki/PKCS_12
 *             - RFC : https://tools.ietf.org/html/rfc7292
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_PKCS12_KEYSTORE_H
#define UNKNOWNECHOCRYPTOMODULE_PKCS12_KEYSTORE_H

#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/key/private_key.h>
#include <ueum/bool.h>

typedef struct {
    uecm_x509_certificate *certificate;
    uecm_private_key *private_key;
    uecm_x509_certificate **other_certificates;
    int other_certificates_number;
    char *friendly_name;
} uecm_pkcs12_keystore;

uecm_pkcs12_keystore *uecm_pkcs12_keystore_create(uecm_x509_certificate *certificate, uecm_private_key *private_key, const char *friendly_name);

uecm_pkcs12_keystore *uecm_pkcs12_keystore_load(const char *file_name, const char *passphrase);

void uecm_pkcs12_keystore_destroy(uecm_pkcs12_keystore *keystore);

void uecm_pkcs12_keystore_destroy_all(uecm_pkcs12_keystore *keystore);

bool uecm_pkcs12_keystore_add_certificate(uecm_pkcs12_keystore *keystore, uecm_x509_certificate *certificate, const unsigned char *friendly_name, size_t friendly_name_size);

bool uecm_pkcs12_keystore_add_certificate_from_file(uecm_pkcs12_keystore *keystore, const char *file_name, const unsigned char *friendly_name, size_t friendly_name_size);

bool uecm_pkcs12_keystore_add_certificate_from_bytes(uecm_pkcs12_keystore *keystore, unsigned char *data, size_t data_size, const unsigned char *friendly_name,
    size_t friendly_name_size);

bool uecm_pkcs12_keystore_add_certificates_bundle(uecm_pkcs12_keystore *keystore, const char *file_name, const char *passphrase);

bool uecm_pkcs12_keystore_remove_certificate(uecm_pkcs12_keystore *keystore, const unsigned char *friendly_name, size_t friendly_name_size);

uecm_x509_certificate *uecm_pkcs12_keystore_find_certificate_by_friendly_name(uecm_pkcs12_keystore *keystore, const unsigned char *friendly_name, size_t friendly_name_size);

bool uecm_pkcs12_keystore_write(uecm_pkcs12_keystore *keystore, const char *file_name, const char *passphrase);

#endif
