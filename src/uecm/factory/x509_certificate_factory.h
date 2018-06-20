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
 *  @file      x509_certificate_factory.h
 *  @brief     Factory to create signed or self-signed X509 certificate.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @todo      Add callback for RSA keypair gen
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_FACTORY_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_FACTORY_H

#include <ueum/bool.h>
#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/key/private_key.h>

bool uecm_x509_certificate_generate_self_signed_ca(char *CN, uecm_x509_certificate **certificate, uecm_private_key **private_key);

bool uecm_x509_certificate_generate_signed(uecm_x509_certificate *ca_certificate, uecm_private_key *ca_private_key,
    char *CN, uecm_x509_certificate **certificate, uecm_private_key **private_key);

#endif
