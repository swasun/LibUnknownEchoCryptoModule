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
 *  @file      rsa_signer_factory.h
 *  @brief     Factory to create RSA signer from key pair.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_RSA_SIGNER_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_RSA_SIGNER_FACTORY_H

#include <uecm/api/signature/signer.h>
#include <uecm/api/key/public_key.h>
#include <uecm/api/key/private_key.h>
#include <uecm/api/key/asym_key.h>

uecm_signer *uecm_rsa_signer_create(uecm_public_key *pk, uecm_private_key *sk, const char *digest_name);

uecm_signer *uecm_rsa_signer_create_default(uecm_public_key *pk, uecm_private_key *sk);

uecm_signer *uecm_rsa_signer_create_sha256(uecm_public_key *pk, uecm_private_key *sk);

uecm_signer *uecm_rsa_signer_create_from_pair(uecm_asym_key *akey, const char *digest_name);

uecm_signer *uecm_rsa_signer_create_default_from_pair(uecm_asym_key *akey);

uecm_signer *uecm_rsa_signer_create_sha256_from_pair(uecm_asym_key *akey);

#endif
