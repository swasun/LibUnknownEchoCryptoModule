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

#include <uecm/byte/byte_stream.h>
#include <uecm/alloc.h>
#include <ei/ei.h>

#include <string.h>

uecm_byte_stream *uecm_byte_stream_create() {
	/* @todo fix default size */
	return uecm_byte_stream_create_size(1024);
}

uecm_byte_stream *uecm_byte_stream_create_size(size_t size) {
	uecm_byte_stream *stream;

    ei_check_parameter_or_return(size > 0);

    uecm_safe_alloc(stream, uecm_byte_stream, 1);

    uecm_safe_alloc_or_goto(stream->bytes, unsigned char, size, clean_up);

    memset(stream->bytes, 0, size);
	/* @todo fix default limit */
    stream->limit = 10000;
    stream->position = 0;
    stream->size = size;

    return stream;

clean_up:
    uecm_byte_stream_destroy(stream);
    return NULL;
}

void uecm_byte_stream_clean_up(uecm_byte_stream *stream) {
	if (!stream) {
        return;
    }

    if (!stream->bytes) {
        return;
    }

    memset(stream->bytes, 0, stream->size);
    stream->position = 0;
}

void uecm_byte_stream_destroy(uecm_byte_stream *stream) {
	if (!stream) {
        return;
    }

    uecm_safe_free(stream->bytes);
    uecm_safe_free(stream);
}

unsigned char *uecm_byte_stream_get_data(uecm_byte_stream *stream) {
	if (!stream || !stream->bytes) {
        return NULL;
    }

    return stream->bytes;
}

size_t uecm_byte_stream_get_position(uecm_byte_stream *stream) {
	if (!stream) {
		ei_stacktrace_push_msg("Specified stream ptr is null");
        return 0;
    }

    return stream->position;
}

bool uecm_byte_stream_set_position(uecm_byte_stream *stream, size_t position) {
    ei_check_parameter_or_return(stream);
    ei_check_parameter_or_return(stream->bytes);
    ei_check_parameter_or_return(stream->limit > 0);
    ei_check_parameter_or_return(position >= 0 && position < 18446744073709551615UL);

	if (position >= stream->limit || position > stream->size) {
		ei_stacktrace_push_msg("Position out of range");
		return false;
	}

    stream->position = position;

    return true;
}

size_t uecm_byte_stream_get_size(uecm_byte_stream *stream) {
    if (!stream) {
		ei_stacktrace_push_msg("Specified stream ptr is null");
        return 0;
    }

    return stream->position;
}

bool uecm_byte_stream_is_empty(uecm_byte_stream *stream) {
    ei_check_parameter_or_return(stream);

    return stream->position <= 0;
}

void uecm_byte_stream_print_hex(uecm_byte_stream *stream, FILE *fd) {
    size_t i;

    fprintf(fd, "0x");
    for (i = 0; i < stream->position; i++) {
        fprintf(fd, "%02x", stream->bytes[i]);
    }
    fprintf(fd, "\n");
}

void uecm_byte_stream_print_string(uecm_byte_stream *stream, FILE *fd) {
    size_t i;

    for (i = 0; i < stream->position; i++) {
        fprintf(fd, "%c", stream->bytes[i]);
    }
    fprintf(fd, "\n");
}

uecm_byte_stream *uecm_byte_stream_copy(uecm_byte_stream *stream) {
	uecm_byte_stream *new_stream;

	uecm_safe_alloc(new_stream, uecm_byte_stream, 1);
	uecm_safe_alloc(new_stream->bytes, unsigned char, stream->size);
	memcpy(new_stream->bytes, stream->bytes, stream->size * sizeof(unsigned char));
	new_stream->limit = stream->limit;
	new_stream->position = stream->position;
	new_stream->size = stream->size;

	return new_stream;
}
