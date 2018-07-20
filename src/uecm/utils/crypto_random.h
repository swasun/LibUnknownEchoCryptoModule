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
 *  @file      crypto_random.h
 *  @brief     Generate crypto random bytes or specific size.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_CRYPTO_RANDOM_H
#define UNKNOWNECHOCRYPTOMODULE_CRYPTO_RANDOM_H

#include <ueum/bool.h>

#include <stddef.h>

/**
 * @brief uecm_crypto_seed_prng
 * @return true if PRNG is seeded, false otherwise
 * @todo test on Windows
 *
 * OpenSSL makes sure that the PRNG state is unique for each thread.
 * On systems that provide /dev/urandom, the randomness device is used to seed the PRNG transparently.
 * However, on all other systems, the application is responsible for seeding the PRNG by calling RAND_add(),
 * RAND_egd(3) or RAND_load_file(3).
 *
 * source : https://wiki.openssl.org/index.php/Manual:RAND_add(3),
 *    https://wiki.openssl.org/index.php/Random_Numbers
 */
bool uecm_crypto_random_seed_prng();

bool uecm_crypto_random_bytes(unsigned char *buffer, size_t buffer_length);

#endif
