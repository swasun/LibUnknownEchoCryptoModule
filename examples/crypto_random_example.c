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

#include <uecm/uecm.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <stddef.h>

int main() {
    unsigned char *buffer;
    size_t buffer_size;

	ei_init_or_die();
    ei_logger_use_symbol_levels();

    buffer = NULL;
    buffer_size = 16;
    
    ei_logger_info("Initializing LibUnknownEchoCryptoModule...");
    if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEchoCryptoModule");
		goto clean_up;
    }
    ei_logger_info("LibUnknownEchoCryptoModule is correctly initialized.");

    ei_logger_info("Allocating 16 bytes...");
    ueum_safe_alloc_or_goto(buffer, unsigned char, buffer_size, clean_up);

    ei_logger_info("Buffer content:");
    if (!ueum_hex_print(buffer, buffer_size, stdout)) {
        ei_stacktrace_push_msg("Failed to print buffer content (empty)");
        goto clean_up;
    }

    ei_logger_info("Generating crypto random bytes...");
    if (!uecm_crypto_random_bytes(buffer, buffer_size)) {
        ei_stacktrace_push_msg("Failed to generate crypto random bytes");
        goto clean_up;
    }

    ei_logger_info("Buffer content:");
    if (!ueum_hex_print(buffer, buffer_size, stdout)) {
        ei_stacktrace_push_msg("Failed to print buffer content (filled)");
        goto clean_up;
    }

    ei_logger_info("Succeed !");

clean_up:
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("Error(s) occurred with the following stacktrace(s):");
        ei_stacktrace_print_all();
    }
    uecm_uninit();
    ei_uninit();
    return 0;
}