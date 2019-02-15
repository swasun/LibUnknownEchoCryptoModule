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
 *  @file      crypto_error_handling.h
 *  @brief     Handle error of crypto module.
 *  @author    Charly Lamothe
 *  @copyright Apache License 2.0.
 */

#ifndef UNKNOWNECHOCRYPTOMODULE_CRYPTO_ERROR_HANDLING_H
#define UNKNOWNECHOCRYPTOMODULE_CRYPTO_ERROR_HANDLING_H

#include <uecm/impl/errorHandling/openssl_error_handling.h>

#define uecm_crypto_error_handling(error_buffer, begin_msg) \
    uecm_openssl_error_handling(error_buffer, begin_msg) \

#endif
