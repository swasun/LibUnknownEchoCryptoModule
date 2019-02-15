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
 *  @file      hasher.h
 *  @brief     Hasher structure to hash message.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_HASHER_H
#define UNKNOWNECHOCRYPTOMODULE_HASHER_H

#include <ueum/ueum.h>

#include <stddef.h>

typedef struct uecm_hasher uecm_hasher;

uecm_hasher *uecm_hasher_create();

void uecm_hasher_destroy(uecm_hasher *h);

bool uecm_hasher_init(uecm_hasher *h, const char *digest_name);

unsigned char *uecm_hasher_digest(uecm_hasher *h, const unsigned char *message, size_t message_len, size_t *digest_len);

int uecm_hasher_get_digest_size(uecm_hasher *h);

#endif
