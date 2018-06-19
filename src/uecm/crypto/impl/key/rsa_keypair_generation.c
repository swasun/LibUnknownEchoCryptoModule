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

#include <uecm/crypto/impl/key/rsa_keypair_generation.h>
#include <uecm/crypto/impl/errorHandling/openssl_error_handling.h>
#include <uecm/crypto/utils/crypto_random.h>
/*#include <uecm/console/progress_bar.h>
#include <uecm/console/color.h>*/
#include <uecm/string/string_utility.h>
#include <ei/ei.h>
#include <uecm/alloc.h>

#include <openssl/bn.h>

/*static int genrsa_callback(int p, int n, BN_GENCB *cb) {
    uecm_progress_bar *progress_bar;

    if (p != 0) {
        progress_bar = (uecm_progress_bar *)BN_GENCB_get_arg(cb);
        uecm_progress_bar_update_by_increasing_and_print(progress_bar, 10);
    }

    return 1;
}*/

RSA *uecm_rsa_keypair_gen(int bits) {
    RSA *rsa_key_pair;
    unsigned long e;
    int ret;
    BIGNUM *bne;
    char *error_buffer;
    /*BN_GENCB *cb;
    uecm_progress_bar *progress_bar;
    const char *progress_bar_description;*/

    if (bits != 2048 && bits != 4096) {
        return NULL;
    }

    rsa_key_pair = NULL;
    bne = NULL;
    e = RSA_F4;
    error_buffer = NULL;
    //cb = BN_GENCB_new();

    /* Create a pretty progress bar */

    /* Build progress bar description */
    //progress_bar_description = uecm_strcat_variadic("sds", "Generating ", bits, " bits RSA key");

    /* Create progress bar ptr with a max size of 100 */
    //progress_bar = uecm_progress_bar_create(100, progress_bar_description, stdout);

    /* Doesn't support Windows coloring for now */
/*#ifdef _WINDOWS
    uecm_progress_bar_set_style(progress_bar, "|", "-");
#else
    uecm_progress_bar_set_colors(progress_bar, UNKNOWNECHOCRYPTOMODULE_COLOR_ID_ATTRIBUTE_DIM, UNKNOWNECHOCRYPTOMODULE_COLOR_ID_FOREGROUND_GREEN, -1);
    uecm_progress_bar_set_style(progress_bar, "\u2588", "-");
#endif*/

    /* Seed the PRNG to increase the entropy */
    if (!uecm_crypto_random_seed_prng()) {
        ei_stacktrace_push_msg("Failed to seed PRNG");
        goto clean_up;
    }

    if ((rsa_key_pair = RSA_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "RSA_new");
        goto clean_up;
    }

    if ((bne = BN_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "BN_new");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }

    if ((ret = BN_set_word(bne, e)) != 1) {
        uecm_openssl_error_handling(error_buffer, "BN_set_word");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }

    //BN_GENCB_set(cb, genrsa_callback, progress_bar);

    /*if (!(ret = RSA_generate_key_ex(rsa_key_pair, bits, bne, cb))) {
        uecm_openssl_error_handling(error_buffer, "RSA_generate_key_ex");
        RSA_free(rsa_key_pair);
        rsa_key_pair = NULL;
        goto clean_up;
    }
    uecm_progress_bar_finish_and_print(progress_bar);*/
	if ((ret = RSA_generate_key_ex(rsa_key_pair, bits, bne, NULL)) == 0) {
		uecm_openssl_error_handling(error_buffer, "RSA_generate_key_ex");
		RSA_free(rsa_key_pair);
		rsa_key_pair = NULL;
		goto clean_up;
	}

    /**
     * @todo fix this
     */
    //fprintf(ei_logger_get_fp(ei_logger_manager_get_logger()), "\n");

    //fprintf(stdout, "\n");
    ei_logger_trace("RSA key generated");

clean_up:
    //BN_GENCB_free(cb);
    BN_clear_free(bne);
    //uecm_safe_free(progress_bar_description);
    //uecm_progress_bar_destroy(progress_bar);
    return rsa_key_pair;
}
