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
 *  @file      defines.h
 *  @brief     Global defines of LibUnknownEcho.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_DEFINES_H
#define UNKNOWNECHOCRYPTOMODULE_DEFINES_H

/* Crypto defines */

#define UNKNOWNECHOCRYPTOMODULE_DEFAULT_CIPHER_NAME              "aes-256-cbc"
#define UNKNOWNECHOCRYPTOMODULE_DEFAULT_DIGEST_NAME              "sha256"

/* X509 generation defines */

#define UNKNOWNECHOCRYPTOMODULE_DEFAULT_X509_NOT_AFTER_YEAR      1
#define UNKNOWNECHOCRYPTOMODULE_DEFAULT_X509_NOT_AFTER_DAYS      365
#define UNKNOWNECHOCRYPTOMODULE_DEFAULT_RSA_KEY_BITS             4096
#define UNKNOWNECHOCRYPTOMODULE_DEFUALT_X509_SERIAL_LENGTH       20

#endif
