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

#ifndef UNKNOWNECHOCRYPTOMODULE_OPENSSL_ERROR_HANDLING_H
#define UNKNOWNECHOCRYPTOMODULE_OPENSSL_ERROR_HANDLING_H

#include <ei/ei.h>
#include <uecm/alloc.h>

char *uecm_openssl_error_handling_impl(char *begin_msg);

#define uecm_openssl_error_handling(error_buffer, begin_msg) \
	do { \
		error_buffer = uecm_openssl_error_handling_impl(begin_msg); \
		ei_stacktrace_push_msg(error_buffer) \
		uecm_safe_str_free(error_buffer) \
	} while (0); \

#endif
