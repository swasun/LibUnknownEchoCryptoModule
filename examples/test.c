#include <uecm/uecm.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <openssl/evp.h>
#include <openssl/aes.h>

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stddef.h>
#include <errno.h>

bool en_de_crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec) {
    bool result;
    EVP_CIPHER_CTX *ctx;
    unsigned short int CHUNK_SIZE;
    unsigned char *read_chunk, *cipher_chunk;
    unsigned block_size;
    int out_len;
    char *error_buffer;
    size_t read_size;

    if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
        uecm_openssl_error_handling(error_buffer, "Cannot create new cipher context");
        return false;
    }

    result = false;
    CHUNK_SIZE = 4096;
    read_chunk = NULL;
    cipher_chunk = NULL;
    error_buffer = NULL;

    ueum_safe_alloc_or_goto(read_chunk, unsigned char, CHUNK_SIZE, clean_up);

    if (!EVP_CipherInit(ctx, EVP_aes_256_cbc(), ckey, ivec, should_encrypt)) {
        uecm_openssl_error_handling(error_buffer, "Cannot init cipher context");
        goto clean_up;
    }

    /* Get the block size of the this cipher, depending of the cipher type setted in EVP_CipherInit() */
    block_size = EVP_CIPHER_CTX_block_size(ctx);

    ueum_safe_alloc_or_goto(cipher_chunk, unsigned char, CHUNK_SIZE + block_size, clean_up);

    /* Read in data in blocks until EOF. Update the ciphering with each read. */
    while (1) {
        /* Read a chunk of size CHUNK_SIZE and check if an error occurred */
        errno = 0;
        read_size = fread(read_chunk, sizeof(unsigned char), CHUNK_SIZE, ifp);
        if (errno != 0) {
            ei_stacktrace_push_msg("Failed to read plain chunk with error message: %s", strerror(errno));
            goto clean_up;
        }

        /* Cipher the chunk */
        if (!EVP_CipherUpdate(ctx, cipher_chunk, &out_len, read_chunk, read_size)) {
            uecm_openssl_error_handling(error_buffer, "Cannot update cipher context");
            goto clean_up;
        }

        /* Write the cipher chunk to the output file and check if an error occurred */
        errno = 0;
        fwrite(cipher_chunk, sizeof(unsigned char), out_len, ofp);
        if (errno != 0) {
            ei_stacktrace_push_msg("Failed to write cipher chunk with error message: %s", strerror(errno));
            goto clean_up;
        }

        /**
         * If read_size is < CHUNK_SIZE, the input file was complete
         * encrypted/decrypted. If read_size is equal to 0, then EVP_CipherFinal()
         * will cipher the remains bytes.
         */
        if (read_size < CHUNK_SIZE) {
            break;
        }
    }

    /* Cipher the last chunk */
    if (!EVP_CipherFinal(ctx, cipher_chunk, &out_len)) {
        uecm_openssl_error_handling(error_buffer, "Cannot process the last chunk of cipher context");
        goto clean_up;
    }

    /* Write the last chunk */
    errno = 0;
    fwrite(cipher_chunk, sizeof(unsigned char), out_len, ofp);
    if (errno != 0) {
        ei_stacktrace_push_msg("Failed to write the last cipher chunk with error message: %s", strerror(errno));
        goto clean_up;
    }

    result = true;

clean_up:
    ueum_safe_free(read_chunk);
    ueum_safe_free(cipher_chunk);
    EVP_CIPHER_CTX_free(ctx);
    return result;
}


int main(int argc, char **argv) {
    /*FILE *in, *out;

    ei_init();

    if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEcho");
		goto clean_up;
	}
    ei_logger_info("UnknownEchoLibCryptoModule is correctly initialized");

    in = NULL;
    out = NULL;

    if ((in = fopen("images2.jpg", "rb")) == NULL) {
        ei_stacktrace_push_errno();
        goto clean_up;
    }

    if ((out = fopen("images2.jpg.enc", "wb")) == NULL) {
        ei_stacktrace_push_errno();
        goto clean_up;
    }

    if (!do_crypt(in, out, 1)) {
        ei_stacktrace_push_msg("gn");
    }

clean_up:
    ueum_safe_fclose(in);
    ueum_safe_fclose(out);
    if (ei_stacktrace_is_filled()) {
        ei_logger_error("An error occurred with the following stacktrace :");
        ei_stacktrace_print_all();
    }
    uecm_uninit();
    ei_uninit();*/

    uecm_sym_key *key;
    unsigned char *iv;
    size_t iv_size;

    ei_init_or_die();
    ei_logger_use_symbol_levels();

    if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEcho");
		exit(1);
	}

    key = NULL;
    iv = NULL;

    ei_logger_info("Generating random key...");
    if ((key = uecm_sym_key_create_random()) == NULL) {
        ei_stacktrace_push_msg("Failed to create random sym key");
        goto clean_up;
    }
    ei_logger_info("Random key generated");

    ei_logger_info("Encrypting specified file...");
    if (!uecm_file_encrypt(argv[1], argv[2], key, &iv, &iv_size)) {
        ei_stacktrace_push_msg("Failed to encrypt file %s", argv[1]);
        goto clean_up;
    }

    //uecm_file_decrypt(argv[2], argv[1], key, iv);

	ei_logger_info("Succeed");

clean_up:
	if (ei_stacktrace_is_filled()) {
		ei_logger_error("Error(s) occurred with the following stacktrace(s) :");
		ei_stacktrace_print_all();
	}
    uecm_sym_key_destroy(key);
    ueum_safe_free(iv);
    uecm_uninit();
    ei_uninit();
    return 0;
}
