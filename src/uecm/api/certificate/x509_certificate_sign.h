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
 *  @file      x509_certificate_sign.h
 *  @brief     Sign, verify X509 certificates.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       x509_certificate.h
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_SIGN_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_SIGN_H

#include <uecm/api/certificate/x509_certificate.h>
#include <uecm/api/certificate/x509_csr.h>
#include <uecm/api/key/private_key.h>
#include <ueum/ueum.h>

uecm_x509_certificate *uecm_x509_certificate_sign_from_csr(uecm_x509_csr *csr, uecm_x509_certificate *ca_certificate, uecm_private_key *ca_private_key);

/**
 *  @todo add chain certificates verification
 */
bool uecm_x509_certificate_verify(uecm_x509_certificate *signed_certificate, uecm_x509_certificate *ca_certificate);

#endif
