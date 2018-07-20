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

#include <uecm/impl/errorHandling/openssl_error_handling.h>
#include <ueum/string/string_utility.h>

#include <openssl/err.h>

char *uecm_openssl_error_handling_impl(char *begin_msg) {
    unsigned long error_code;
    char *error_buffer;

    error_buffer = NULL;

    error_code = ERR_get_error();
    error_buffer = (char *)ERR_reason_error_string(error_code);
    if (error_buffer) {
        error_buffer = ueum_strcat_variadic("ssss", begin_msg, " - failed with error msg `", error_buffer, "`");
    } else {
        error_buffer = ueum_strcat_variadic("ssl", begin_msg, " - failed with error code ", error_code);
    }

    return error_buffer;
}
