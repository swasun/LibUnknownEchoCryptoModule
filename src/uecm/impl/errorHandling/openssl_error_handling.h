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

#ifndef UNKNOWNECHOCRYPTOMODULE_OPENSSL_ERROR_HANDLING_H
#define UNKNOWNECHOCRYPTOMODULE_OPENSSL_ERROR_HANDLING_H

#include <ei/ei.h>
#include <ueum/ueum.h>

char *uecm_openssl_error_handling_impl(char *begin_msg);

#define uecm_openssl_error_handling(error_buffer, begin_msg) \
    do { \
        error_buffer = uecm_openssl_error_handling_impl(begin_msg); \
        ei_stacktrace_push_msg(error_buffer) \
        ueum_safe_str_free(error_buffer) \
    } while (0); \

#endif
