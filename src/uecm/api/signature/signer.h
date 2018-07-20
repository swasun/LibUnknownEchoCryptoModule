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
 *  @file      signer.h
 *  @brief     Signer structure that sign/verify binary data.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_SIGNER_H
#define UNKNOWNECHOCRYPTOMODULE_SIGNER_H

#include <uecm/api/key/public_key.h>
#include <uecm/api/key/private_key.h>
#include <ueum/bool.h>

#include <stddef.h>

typedef struct uecm_signer uecm_signer;

uecm_signer *uecm_signer_create(const char *digest_name);

void uecm_signer_destroy(uecm_signer *signer);

bool uecm_signer_set_public_key(uecm_signer *signer, uecm_public_key *public_key);

bool uecm_signer_set_private_key(uecm_signer *signer, uecm_private_key *private_key);

bool uecm_signer_sign_buffer(uecm_signer *signer, const unsigned char *buf, size_t buf_length, unsigned char **signature, size_t *signature_length);

bool uecm_signer_verify_buffer(uecm_signer *signer, const unsigned char *buf, size_t buf_length, unsigned char *signature, size_t signature_length);

#endif
