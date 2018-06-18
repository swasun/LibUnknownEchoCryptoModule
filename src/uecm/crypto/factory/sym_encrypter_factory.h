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
 *  @file      sym_encrypter_factory.h
 *  @brief     Factory to create Symmetric Encrypter from Symmetric Key (default is AES-CBC-256).
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_SYM_ENCRYPTER_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_SYM_ENCRYPTER_FACTORY_H

#include <uecm/crypto/api/encryption/sym_encrypter.h>
#include <uecm/crypto/api/key/sym_key.h>

uecm_sym_encrypter *uecm_sym_encrypter_aes_cbc_create(uecm_sym_key *key);

uecm_sym_encrypter *uecm_sym_encrypter_rc4_create(uecm_sym_key *key);

uecm_sym_encrypter *uecm_sym_encrypter_default_create(uecm_sym_key *key);

#endif
