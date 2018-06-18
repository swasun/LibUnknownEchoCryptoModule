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

#ifndef UNKNOWNECHOCRYPTOMODULE_UECM_H
#define UNKNOWNECHOCRYPTOMODULE_UECM_H

#include <uecm/bool.h>
#include <uecm/alloc.h>
#include <uecm/init.h>

#include <uecm/crypto/api/certificate/x509_certificate.h>
#include <uecm/crypto/api/certificate/x509_certificate_generation.h>
#include <uecm/crypto/api/certificate/x509_certificate_parameters.h>
#include <uecm/crypto/api/certificate/x509_certificate_sign.h>
#include <uecm/crypto/api/certificate/x509_csr.h>
#include <uecm/crypto/api/cipher/data_cipher.h>
#include <uecm/crypto/api/compression/compress.h>
#include <uecm/crypto/api/crypto_init.h>
#include <uecm/crypto/api/crypto_metadata.h>
#include <uecm/crypto/api/csr/csr_request.h>
#include <uecm/crypto/api/encoding/base64_decode.h>
#include <uecm/crypto/api/encoding/base64_encode.h>
#include <uecm/crypto/api/encryption/sym_encrypter.h>
#include <uecm/crypto/api/errorHandling/crypto_error_handling.h>
#include <uecm/crypto/api/hash/hasher.h>
#include <uecm/crypto/api/key/asym_key.h>
#include <uecm/crypto/api/key/private_key.h>
#include <uecm/crypto/api/key/public_key.h>
#include <uecm/crypto/api/key/sym_key.h>
#include <uecm/crypto/api/keystore/pkcs12_keystore.h>
#include <uecm/crypto/api/signature/signer.h>

#include <uecm/crypto/factory/crypto_metadata_factory.h>
#include <uecm/crypto/factory/hasher_factory.h>
#include <uecm/crypto/factory/pkcs12_keystore_factory.h>
#include <uecm/crypto/factory/rsa_asym_key_factory.h>
#include <uecm/crypto/factory/rsa_signer_factory.h>
#include <uecm/crypto/factory/sym_encrypter_factory.h>
#include <uecm/crypto/factory/sym_key_factory.h>
#include <uecm/crypto/factory/x509_certificate_factory.h>

#endif
