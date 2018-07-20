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
 *  @file      pkcs12_keystore_factory.h
 *  @brief     Factory to create PKCS12 keystore from scratch or from file.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_PKCS12_KEYSTORE_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_PKCS12_KEYSTORE_FACTORY_H

#include <uecm/api/keystore/pkcs12_keystore.h>

uecm_pkcs12_keystore *uecm_pkcs12_keystore_create_random(char *CN, char *friendly_name);

uecm_pkcs12_keystore *uecm_pkcs12_keystore_create_from_files(char *certificate_path, char *private_key_path, const char *private_key_password, char *friendly_name);

#endif
