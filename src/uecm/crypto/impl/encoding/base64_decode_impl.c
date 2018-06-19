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

#include <uecm/crypto/impl/encoding/base64_decode_impl.h>

#include <stdlib.h>

static const unsigned char uecm_base64_table[65] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/*void *_memset(void *s, int c, size_t n) {
    char *p = s;

    while (n--) {
        *p++ = c;
    }

    return s;
}*/

/**
 * uecm_base64_decode - Base64 decode
 * @src: Data to be decoded
 * @len: Length of the data to be decoded
 * @out_len: Pointer to output length variable
 * Returns: Allocated buffer of out_len bytes of decoded data,
 * or %NULL on failure
 */
unsigned char *uecm_base64_decode_impl(const unsigned char *src, size_t len, size_t *out_len) {
    unsigned char dtable[256], *out, *pos, block[4], tmp;
    size_t i, count, olen;
    int pad = 0;

    //_memset(dtable, 0x80, 256);
	memset(dtable, 0x80, 256);
    for (i = 0; i < sizeof(uecm_base64_table) - 1; i++) {
        dtable[uecm_base64_table[i]] = (unsigned char) i;
    }
    dtable['='] = 0;

    count = 0;
    for (i = 0; i < len; i++) {
        if (dtable[src[i]] != 0x80) {
            count++;
        }
    }

    if (count == 0 || count % 4) {
        return NULL;
    }

    olen = count / 4 * 3;
    pos = out = malloc(olen);
    if (out == NULL) {
        return NULL;
    }

    count = 0;
    for (i = 0; i < len; i++) {
        tmp = dtable[src[i]];
        if (tmp == 0x80) {
            continue;
        }

        if (src[i] == '=') {
            pad++;
        }
        block[count] = tmp;
        count++;
        if (count == 4) {
            *pos++ = (block[0] << 2) | (block[1] >> 4);
            *pos++ = (block[1] << 4) | (block[2] >> 2);
            *pos++ = (block[2] << 6) | block[3];
            count = 0;
            if (pad) {
                if (pad == 1) {
                    pos--;
                }
                else if (pad == 2) {
                    pos -= 2;
                }
                else {
                    /* Invalid padding */
                    free(out);
                    return NULL;
                }
                break;
            }
        }
    }

    *out_len = pos - out;
    return out;
}
