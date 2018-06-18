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

#include <uecm/crypto/api/certificate/x509_certificate_parameters.h>
#include <uecm/crypto/utils/crypto_random.h>
#include <uecm/alloc.h>
#include <uecm/string/string_utility.h>
#include <uecm/defines.h>

struct uecm_x509_certificate_parameters {
    unsigned char *serial;
    int serial_length;
    int bits;
    int days;
    char *C;
    char *CN;
    char *OU;
    char *O;
    char *basic_constraint;
    char *subject_key_identifier;
    char *cert_type;
    bool self_signed;
};

uecm_x509_certificate_parameters *uecm_x509_certificate_parameters_create() {
    uecm_x509_certificate_parameters *parameters;

    uecm_safe_alloc(parameters, uecm_x509_certificate_parameters, 1);
    uecm_safe_alloc(parameters->serial, unsigned char, UNKNOWNECHOCRYPTOMODULE_DEFUALT_X509_SERIAL_LENGTH);
	if (!uecm_crypto_random_bytes(parameters->serial, UNKNOWNECHOCRYPTOMODULE_DEFUALT_X509_SERIAL_LENGTH)) {
		ei_stacktrace_push_msg("Failed to gen crypto random bytes");
		return false;
	}
    /* @todo set default serial length in defines */
    parameters->serial_length = UNKNOWNECHOCRYPTOMODULE_DEFUALT_X509_SERIAL_LENGTH;
    /* Ensure serial is positive */
	parameters->serial[0] &= 0x7f;

    parameters->bits = UNKNOWNECHOCRYPTOMODULE_DEFAULT_RSA_KEY_BITS;
    parameters->days = UNKNOWNECHOCRYPTOMODULE_DEFAULT_X509_NOT_AFTER_DAYS;
    parameters->C = NULL;
    parameters->CN = NULL;
    parameters->basic_constraint = NULL;
    parameters->subject_key_identifier = NULL;
    parameters->cert_type = NULL;
    parameters->self_signed = false;

    return parameters;
}

void uecm_x509_certificate_parameters_destroy(uecm_x509_certificate_parameters *parameters) {
    if (parameters) {
        uecm_safe_free(parameters->C);
        uecm_safe_free(parameters->CN);
        uecm_safe_free(parameters->basic_constraint);
        uecm_safe_free(parameters->subject_key_identifier);
        uecm_safe_free(parameters->cert_type);
        uecm_safe_free(parameters->serial);
        uecm_safe_free(parameters);
    }
}

unsigned char *uecm_x509_certificate_parameters_get_serial(uecm_x509_certificate_parameters *parameters) {
    return parameters->serial;
}

int uecm_x509_certificate_parameters_get_serial_length(uecm_x509_certificate_parameters *parameters) {
    return parameters->serial_length;
}

bool uecm_x509_certificate_parameters_set_bits(uecm_x509_certificate_parameters *parameters, int bits) {
    parameters->bits = bits;
    return true;
}

int uecm_x509_certificate_parameters_get_bits(uecm_x509_certificate_parameters *parameters) {
    return parameters->bits;
}

bool uecm_x509_certificate_parameters_set_days(uecm_x509_certificate_parameters *parameters, int days) {
    parameters->days = days;
    return true;
}

int uecm_x509_certificate_parameters_get_days(uecm_x509_certificate_parameters *parameters) {
    return parameters->days;
}

bool uecm_x509_certificate_parameters_set_country(uecm_x509_certificate_parameters *parameters, char *country) {
    parameters->C = uecm_string_create_from(country);
    return true;
}

char *uecm_x509_certificate_parameters_get_country(uecm_x509_certificate_parameters *parameters) {
    return parameters->C;
}

bool uecm_x509_certificate_parameters_set_common_name(uecm_x509_certificate_parameters *parameters, char *common_name) {
    parameters->CN = uecm_string_create_from(common_name);
    return true;
}

char *uecm_x509_certificate_parameters_get_common_name(uecm_x509_certificate_parameters *parameters) {
    return parameters->CN;
}

bool uecm_x509_certificate_parameters_set_organizational_unit(uecm_x509_certificate_parameters *parameters, char *organizational_unit) {
    parameters->OU = uecm_string_create_from(organizational_unit);
    return true;
}

char *uecm_x509_certificate_parameters_get_oranizational_unit(uecm_x509_certificate_parameters *parameters) {
    return parameters->OU;
}

bool uecm_x509_certificate_parameters_set_organization(uecm_x509_certificate_parameters *parameters, char *organization) {
    parameters->O = uecm_string_create_from(organization);
    return true;
}

char *uecm_x509_certificate_parameters_get_oranization(uecm_x509_certificate_parameters *parameters) {
    return parameters->O;
}

bool uecm_x509_certificate_parameters_set_ca_type(uecm_x509_certificate_parameters *parameters) {
    parameters->basic_constraint = uecm_string_create_from("CA:TRUE");
    parameters->cert_type = uecm_string_create_from("sslCA");
    return true;
}

char *uecm_x509_certificate_parameters_get_constraint(uecm_x509_certificate_parameters *parameters) {
    return parameters->basic_constraint;
}

char *uecm_x509_certificate_parameters_get_cert_type(uecm_x509_certificate_parameters *parameters) {
    return parameters->cert_type;
}

bool uecm_x509_certificate_parameters_set_subject_key_identifier_as_hash(uecm_x509_certificate_parameters *parameters) {
    parameters->subject_key_identifier = uecm_string_create_from("hash");
    return true;
}

char *uecm_x509_certificate_parameters_get_subject_key_identifier(uecm_x509_certificate_parameters *parameters) {
    return parameters->subject_key_identifier;
}

bool uecm_x509_certificate_parameters_set_self_signed(uecm_x509_certificate_parameters *parameters) {
    parameters->self_signed = true;
    return true;
}

bool uecm_x509_certificate_parameters_is_self_signed(uecm_x509_certificate_parameters *parameters) {
    return parameters->self_signed;
}
