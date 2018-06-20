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
 *  @file      rsa_asym_key_factory.h
 *  @brief     Factory to create RSA Asymmetric Key. Random, from files, from
 *             already existing certificate.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @todo      Add callback for RSA key generation
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_RSA_ASYM_KEY_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_RSA_ASYM_KEY_FACTORY_H

#include <uecm/api/key/asym_key.h>
#include <uecm/api/key/public_key.h>
#include <uecm/api/key/private_key.h>
#include <uecm/api/certificate/x509_certificate.h>

uecm_asym_key *uecm_rsa_asym_key_create(int bits);

uecm_public_key *uecm_rsa_public_key_create_pk_from_file(char *file_path);

uecm_private_key *uecm_rsa_private_key_create_sk_from_file(char *file_path);

uecm_asym_key *uecm_rsa_asym_key_create_from_files(char *pk_file_path, char *sk_file_path);

uecm_public_key *uecm_rsa_public_key_from_x509_certificate(uecm_x509_certificate *certificate);

uecm_private_key *uecm_rsa_private_key_from_key_certificate(const char *file_name);

#endif
