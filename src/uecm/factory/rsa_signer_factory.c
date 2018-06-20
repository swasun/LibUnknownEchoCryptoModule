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

#include <uecm/factory/rsa_signer_factory.h>
#include <uecm/factory/hasher_factory.h>
#include <ei/ei.h>

uecm_signer *uecm_rsa_signer_create(uecm_public_key *pk, uecm_private_key *sk, const char *digest_name) {
	uecm_signer *signer;

	if (!pk) {
		ei_stacktrace_push_msg("Specified public key is null");
		return NULL;
	}

	if (!sk) {
		ei_stacktrace_push_msg("Specified private key is null");
		return NULL;
	}

	if ((signer = uecm_signer_create(digest_name)) == NULL) {
		ei_stacktrace_push_msg("Failed to create signer");
		return NULL;
	}

	uecm_signer_set_public_key(signer, pk);
	uecm_signer_set_private_key(signer, sk);

	return signer;
}

uecm_signer *uecm_rsa_signer_create_default(uecm_public_key *pk, uecm_private_key *sk) {
	return uecm_rsa_signer_create_sha256(pk, sk);
}

uecm_signer *uecm_rsa_signer_create_sha256(uecm_public_key *pk, uecm_private_key *sk) {
	return uecm_rsa_signer_create(pk, sk, "sha256");
}

uecm_signer *uecm_rsa_signer_create_from_pair(uecm_asym_key *akey, const char *digest_name) {
	return uecm_rsa_signer_create(akey->pk, akey->sk, digest_name);
}

uecm_signer *uecm_rsa_signer_create_default_from_pair(uecm_asym_key *akey) {
	return uecm_rsa_signer_create_default(akey->pk, akey->sk);
}

uecm_signer *uecm_rsa_signer_create_sha256_from_pair(uecm_asym_key *akey) {
	return uecm_rsa_signer_create_sha256(akey->pk, akey->sk);
}
