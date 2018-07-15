#include <uecm/uecm.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <openssl/evp.h>

#include <stdio.h>

int do_crypt(FILE *in, FILE *out, int do_encrypt)
{
/* Allow enough space in output buffer for additional block */
unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
int inlen, outlen;
EVP_CIPHER_CTX *ctx;
/* Bogus key and IV: we'd normally set these from
    * another source.
    */
unsigned char key[] = "0123456789abcdeF";
unsigned char iv[] = "1234567887654321";

/* Don't set key or IV right away; we want to check lengths */
if ((ctx = EVP_CIPHER_CTX_new()) == NULL) {
    perror("EVP_CIPHER_CTX_new");
    return -1;
}
EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
        do_encrypt);
OPENSSL_assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
OPENSSL_assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

/* Now we can set key and IV */
EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

for(;;)
        {
        inlen = fread(inbuf, 1, 1024, in);
        if (inlen <= 0) break;
        if(!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen))
                {
                /* Error */
                perror("EVP_CipherUpdate");
                EVP_CIPHER_CTX_free(ctx);
                return 0;
                }
        fwrite(outbuf, 1, outlen, out);
        }
if(!EVP_CipherFinal_ex(ctx, outbuf, &outlen))
        {
        /* Error */
        perror("EVP_CipherFinal_ex");
        EVP_CIPHER_CTX_free(ctx);
        return 0;
        }
fwrite(outbuf, 1, outlen, out);

EVP_CIPHER_CTX_free(ctx);
return 1;
}

int main(int argc, char **argv) {
    FILE *in, *out;

    ei_init();

    if (!uecm_init()) {
		ei_stacktrace_push_msg("Failed to initialize LibUnknownEcho");
		goto clean_up;
	}
    ei_logger_info("UnknownEchoLibCryptoModule is correctly initialized");

    in = NULL;
    out = NULL;

    if ((in = fopen(argv[1], "rb")) == NULL) {
        ei_stacktrace_push_errno();
        goto clean_up;
    }

    if ((out = fopen(argv[2], "wb")) == NULL) {
        ei_stacktrace_push_errno();
        goto clean_up;
    }

    do_crypt(in, out, atoi(argv[3]));

clean_up:
    ueum_safe_fclose(in);
    ueum_safe_fclose(out);
    ei_logger_stacktrace("An error occured with the following stacktrace:");
    uecm_uninit();
    ei_uninit();
}
