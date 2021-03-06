/*******************************************************************************
 * Copyright (C) 2018 Charly Lamothe                                           *
 *                                                                             *
 * This file is part of LibUnknownEchoCryptoModule.                            *
 *                                                                             *
 *   Licensed under the Apache License, Version 2.0 (the "License");           *
 *   you may not use this file except in compliance with the License.          *
 *   You may obtain a copy of the License at                                   *
 *                                                                             *
 *   http://www.apache.org/licenses/LICENSE-2.0                                *
 *                                                                             *
 *   Unless required by applicable law or agreed to in writing, software       *
 *   distributed under the License is distributed on an "AS IS" BASIS,         *
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  *
 *   See the License for the specific language governing permissions and       *
 *   limitations under the License.                                            *
 *******************************************************************************/

/**
 *  @file      x509_certificate_factory.h
 *  @brief     Factory to create signed or self-signed X509 certificate.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 *  @todo      Add callback for RSA keypair gen
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_FACTORY_H

#include <ueum/ueum.h>
#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/key/private_key.h>

bool uecm_x509_certificate_generate_self_signed_ca(char *CN, uecm_x509_certificate **certificate, uecm_private_key **private_key);

bool uecm_x509_certificate_generate_signed(uecm_x509_certificate *ca_certificate, uecm_private_key *ca_private_key,
    char *CN, uecm_x509_certificate **certificate, uecm_private_key **private_key);

#endif
