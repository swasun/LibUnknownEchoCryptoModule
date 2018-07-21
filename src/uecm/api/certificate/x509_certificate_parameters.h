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
 *  @file      x509_certificate_parameters.h
 *  @brief     Structure to store parameters of an X509 certificate, to generate a parameterized certificate.
 *  @author    Charly Lamothe
 *  @copyright GNU Public License.
 *  @see       x509_certificate_generation.h
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_PARAMETERS_H
#define UNKNOWNECHOCRYPTOMODULE_X509_CERTIFICATE_PARAMETERS_H

#include <ueum/ueum.h>

typedef struct uecm_x509_certificate_parameters uecm_x509_certificate_parameters;

uecm_x509_certificate_parameters *uecm_x509_certificate_parameters_create();

void uecm_x509_certificate_parameters_destroy(uecm_x509_certificate_parameters *parameters);

unsigned char *uecm_x509_certificate_parameters_get_serial(uecm_x509_certificate_parameters *parameters);

int uecm_x509_certificate_parameters_get_serial_length(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_bits(uecm_x509_certificate_parameters *parameters, int bits);

int uecm_x509_certificate_parameters_get_bits(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_days(uecm_x509_certificate_parameters *parameters, int days);

int uecm_x509_certificate_parameters_get_days(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_country(uecm_x509_certificate_parameters *parameters, char *country);

char *uecm_x509_certificate_parameters_get_country(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_common_name(uecm_x509_certificate_parameters *parameters, char *common_name);

char *uecm_x509_certificate_parameters_get_common_name(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_organizational_unit(uecm_x509_certificate_parameters *parameters, char *organizational_unit);

char *uecm_x509_certificate_parameters_get_oranizational_unit(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_organization(uecm_x509_certificate_parameters *parameters, char *organization);

char *uecm_x509_certificate_parameters_get_oranization(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_ca_type(uecm_x509_certificate_parameters *parameters);

char *uecm_x509_certificate_parameters_get_constraint(uecm_x509_certificate_parameters *parameters);

char *uecm_x509_certificate_parameters_get_cert_type(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_subject_key_identifier_as_hash(uecm_x509_certificate_parameters *parameters);

char *uecm_x509_certificate_parameters_get_subject_key_identifier(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_set_self_signed(uecm_x509_certificate_parameters *parameters);

bool uecm_x509_certificate_parameters_is_self_signed(uecm_x509_certificate_parameters *parameters);

#endif
