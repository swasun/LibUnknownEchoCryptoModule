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
 *  @file      hasher_factory.h
 *  @brief     Factory that create an Hasher (default is SHA-256).
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_HASHER_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_HASHER_FACTORY_H

#include <uecm/api/hash/hasher.h>

uecm_hasher *uecm_hasher_sha256_create();

uecm_hasher *uecm_hasher_default_create();

#endif
