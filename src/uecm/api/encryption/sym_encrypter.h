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
 *  @file      sym_encrypter.h
 *  @brief     Symmetric Encrypter structure to encrypt/decrypt with unique key.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_SYM_ENCRYPTER_H
#define UNKNOWNECHOCRYPTOMODULE_SYM_ENCRYPTER_H

#include <uecm/api/key/sym_key.h>
#include <ueum/ueum.h>

#include <stddef.h>

typedef struct uecm_sym_encrypter uecm_sym_encrypter;

uecm_sym_encrypter *uecm_sym_encrypter_create(const char *cipher_name);

void uecm_sym_encrypter_destroy(uecm_sym_encrypter *encrypter);

void uecm_sym_encrypter_destroy_all(uecm_sym_encrypter *encrypter);

uecm_sym_key *uecm_sym_encrypter_get_key(uecm_sym_encrypter *encrypter);

bool uecm_sym_encrypter_set_key(uecm_sym_encrypter *encrypter, uecm_sym_key *key);

size_t uecm_sym_encrypter_get_iv_size(uecm_sym_encrypter *encrypter);

bool uecm_sym_encrypter_encrypt(uecm_sym_encrypter *encrypter, unsigned char *plaintext, size_t plaintext_size, unsigned char *iv, unsigned char **ciphertext, size_t *ciphertext_size);

bool uecm_sym_encrypter_decrypt(uecm_sym_encrypter *encrypter, unsigned char *ciphertext, size_t ciphertext_size, unsigned char *iv, unsigned char **plaintext, size_t *plaintext_size);

#endif
