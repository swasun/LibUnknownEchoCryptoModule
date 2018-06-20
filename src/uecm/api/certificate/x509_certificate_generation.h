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
 *  @file      x509_certificate_generation.h
 *  @brief     Generate X509 certificates.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       x509_certificate.h
 *  @see       x509_certificate_parameters.h
 *  @todo      add callback for RSA generation
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CERTFICATE_GENERATION_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CERTFICATE_GENERATION_H

#include <ueum/bool.h>
#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/certificate/x509_certificate_parameters.h>
#include <uecm/api/key/private_key.h>

#include <stddef.h>

bool uecm_x509_certificate_generate(uecm_x509_certificate_parameters *parameters, uecm_x509_certificate **certificate, uecm_private_key **private_key);

bool uecm_x509_certificate_print_pair(uecm_x509_certificate *certificate, uecm_private_key *private_key,
    char *certificate_file_name, char *private_key_file_name, char *passphrase);

#endif
