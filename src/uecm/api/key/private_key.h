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
 *  @file      private_key.h
 *  @brief     Private key structure.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
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
