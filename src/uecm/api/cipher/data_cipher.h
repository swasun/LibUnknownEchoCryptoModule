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

/**
 *  @file      data_cipher.h
 *  @brief     Data cipher that provides Integrity, Non-Repudiation and Authentification of datas, using Symmetric and Asymmetric Cryptography,
 *             Hashing, Compressing.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_DATA_CIPHER_H
#define UNKNOWNECHOCRYPTOMODULE_DATA_CIPHER_H

#include <uecm/api/key/public_key.h>
#include <uecm/api/key/private_key.h>
#include <uecm/api/key/sym_key.h>
#include <ueum/ueum.h>

#include <stddef.h>

bool uecm_cipher_plain_data(unsigned char *plain_data, size_t plain_data_size,
    uecm_public_key *public_key, uecm_private_key *private_key,
    unsigned char **cipher_data, size_t *cipher_data_size, const char *cipher_name,
    const char *digest_name);

bool uecm_decipher_cipher_data(unsigned char *cipher_data,
    size_t cipher_data_size, uecm_private_key *private_key,
    uecm_public_key *public_key, unsigned char **plain_data,
    size_t *plain_data_size, const char *cipher_name,
    const char *digest_name);

bool uecm_cipher_plain_data_default(unsigned char *plain_data, size_t plain_data_size,
    uecm_public_key *public_key, unsigned char **cipher_data, size_t *cipher_data_size);

bool uecm_decipher_cipher_data_default(unsigned char *cipher_data,
    size_t cipher_data_size, uecm_private_key *private_key,
    unsigned char **plain_data, size_t *plain_data_size);

#endif
