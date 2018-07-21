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

/**
 *  @file      private_key.h
 *  @brief     Private key structure.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_PRIVATE_KEY_H
#define UNKNOWNECHOCRYPTOMODULE_PRIVATE_KEY_H

#include <ueum/ueum.h>

#include <stdio.h>
#include <stddef.h>

typedef enum {
    RSA_PRIVATE_KEY
} uecm_private_key_type;

typedef struct uecm_private_key uecm_private_key;

uecm_private_key *uecm_private_key_create_from_impl(void *impl);

uecm_private_key *uecm_private_key_create(uecm_private_key_type key_type, void *impl, int bits);

void uecm_private_key_destroy(uecm_private_key *sk);

int uecm_private_key_size(uecm_private_key *sk);

//bool uecm_private_key_is_valid(uecm_private_key *sk);

void *uecm_private_key_get_impl(uecm_private_key *sk);

void *uecm_private_key_get_rsa_impl(uecm_private_key *sk);

bool uecm_private_key_print(uecm_private_key *sk, FILE *out_fd, char *passphrase);

#endif
