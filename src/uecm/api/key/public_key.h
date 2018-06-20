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
 *  @file      public_key.h
 *  @brief     Public key structure.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_PUBLIC_KEY_H
#define UNKNOWNECHOCRYPTOMODULE_PUBLIC_KEY_H

#include <ueum/bool.h>

#include <stdio.h>

typedef enum {
	RSA_PUBLIC_KEY
} uecm_public_key_type;

typedef struct uecm_public_key uecm_public_key;

uecm_public_key *uecm_public_key_create(uecm_public_key_type key_type, void *impl, int bits);

void uecm_public_key_destroy(uecm_public_key *pk);

int uecm_public_key_size(uecm_public_key *pk);

//bool uecm_public_key_is_valid(uecm_public_key *pk);

void *uecm_public_key_get_impl(uecm_public_key *pk);

void *uecm_public_key_get_rsa_impl(uecm_public_key *pk);

bool uecm_public_key_print(uecm_public_key *pk, FILE *out_fd);

#endif
