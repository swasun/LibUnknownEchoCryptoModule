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
 *  @file      data_cipher.h
 *  @brief     Data cipher that provides Integrity, Non-Repudiation and Authentification of datas, using Symmetric and Asymmetric Cryptography,
 *             Hashing, Compressing.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_DATA_CIPHER_H
#define UNKNOWNECHOCRYPTOMODULE_DATA_CIPHER_H

#include <uecm/api/key/public_key.h>
#include <uecm/api/key/private_key.h>
#include <uecm/api/key/sym_key.h>
#include <ueum/bool.h>

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
