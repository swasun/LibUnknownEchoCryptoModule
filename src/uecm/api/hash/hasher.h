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
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the                          *
 *   GNU General Public License for more details.                                         *
 *                                                                                        *
 *   You should have received a copy of the GNU General Public License                    *
 *   along with LibUnknownEchoCryptoModule.  If not, see <http://www.gnu.org/licenses/>.  *
 ******************************************************************************************/

/**
 *  @file      hasher.h
 *  @brief     Hasher structure to hash message.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
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
