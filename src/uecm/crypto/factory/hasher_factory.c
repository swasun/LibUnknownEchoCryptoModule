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

#include <uecm/crypto/factory/hasher_factory.h>
#include <ei/ei.h>

uecm_hasher *uecm_hasher_sha256_create() {
    uecm_hasher *h;

    if ((h = uecm_hasher_create()) == NULL) {
        ei_stacktrace_push_msg("Failed to create uecm_hasher");
        return NULL;
    }

    if (!(uecm_hasher_init(h, "sha256"))) {
        ei_stacktrace_push_msg("Failed to initialize uecm_hasher with SHA-256 algorithm");
        uecm_hasher_destroy(h);
        return NULL;
    }

    return h;
}

uecm_hasher *uecm_hasher_default_create() {
    return uecm_hasher_sha256_create();
}
