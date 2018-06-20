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
 *  @file      asym_key.h
 *  @brief     Asymmetric Key structure.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_ASYM_KEY_H
#define UNKNOWNECHOCRYPTOMODULE_ASYM_KEY_H

#include <uecm/api/key/public_key.h>
#include <uecm/api/key/private_key.h>
#include <ueum/bool.h>

#include <stdio.h>
#include <stddef.h>

typedef struct {
    uecm_public_key *pk;
    uecm_private_key *sk;
} uecm_asym_key;

uecm_asym_key *uecm_asym_key_create(uecm_public_key *pk, uecm_private_key *sk);

void uecm_asym_key_destroy(uecm_asym_key *akey);

void uecm_asym_key_destroy_all(uecm_asym_key *akey);

//bool uecm_asym_key_is_valid(uecm_asym_key *akey);

bool uecm_asym_key_print(uecm_asym_key *akey, FILE *out_fd, char *passphrase);

#endif
