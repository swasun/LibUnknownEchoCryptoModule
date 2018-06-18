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

#include <uecm/crypto/api/key/asym_key.h>
#include <uecm/alloc.h>
#include <ei/ei.h>

uecm_asym_key *uecm_asym_key_create(uecm_public_key *pk, uecm_private_key *sk) {
	uecm_asym_key *akey;

	uecm_safe_alloc(akey, uecm_asym_key, 1)
	akey->pk = pk;
	akey->sk = sk;

	return akey;
}

void uecm_asym_key_destroy(uecm_asym_key *akey){
	uecm_safe_free(akey);
}


void uecm_asym_key_destroy_all(uecm_asym_key *akey){
	if (akey) {
		uecm_public_key_destroy(akey->pk);
		uecm_private_key_destroy(akey->sk);
		uecm_safe_free(akey);
	}
}

bool uecm_asym_key_is_valid(uecm_asym_key *akey){
	return akey && akey->pk && akey->sk &&
		uecm_public_key_is_valid(akey->pk) &&
		uecm_private_key_is_valid(akey->sk);
}

bool uecm_asym_key_print(uecm_asym_key *akey, FILE *out_fd, char *passphrase) {
	if (!akey || !akey->pk || !akey->sk) {
		return false;
	}

	uecm_public_key_print(akey->pk, out_fd);
    uecm_private_key_print(akey->sk, out_fd, passphrase);

	return true;
}
