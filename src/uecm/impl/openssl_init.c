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

#include <uecm/impl/openssl_init.h>
#include <ueum/ueum.h>
#include <ei/ei.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/engine.h>
#include <openssl/conf.h>

#if defined (_WIN32) || (_WIN64)
    #undef UNICODE
    #define UNICODE
    #undef _WINSOCKAPI_
    #define _WINSOCKAPI_
    #include <Windows.h>
    #include <winsock2.h>
#else
    #include <pthread.h>
#endif

/* This array will store all of the mutexes available to OpenSSL */
#if defined (_WIN32) || (_WIN64)
    CRITICAL_SECTION *mutex_buf = 0;
#else
    pthread_mutex_t *mutex_buf = 0;
#endif

/* OpenSSL callback to utilize static locks */
void openssl_locking_function_callback(int mode, int n, const char *file, int line) {
    (void)file;
    (void)line;

    if (mode & CRYPTO_LOCK) {
        #if defined(_WIN32) || defined(_WIN64)
            EnterCriticalSection(&mutex_buf[n]);
        #else
            pthread_mutex_lock(&mutex_buf[n]);
        #endif
    }
    else {
        #if defined(_WIN32) || defined(_WIN64)
            LeaveCriticalSection(&mutex_buf[n]);
        #else
            pthread_mutex_unlock(&mutex_buf[n]);
        #endif
    }
}

unsigned long openssl_id_function_callback() {
    #if defined(_WIN32) || defined(_WIN64)
        return ((unsigned long)GetCurrentThreadId());
    #else
        return ((unsigned long)pthread_self());
    #endif
}

static bool alloc_mutexes() {
    int i, total;

    total = CRYPTO_num_locks();
    mutex_buf = NULL;

    #if defined(_WIN32) || defined(_WIN64)
        ueum_safe_alloc(mutex_buf, CRITICAL_SECTION, total);
    #else
        ueum_safe_alloc(mutex_buf, pthread_mutex_t, total);
    #endif

    for (i = 0; i < total;  i++) {
        #if defined(_WIN32) || defined(_WIN64)
            InitializeCriticalSection(&(mutex_buf[i]));
        #else
            pthread_mutex_init(&(mutex_buf[i]), 0);
        #endif
    }

    return true;
}

static void dealloc_mutexes() {
    int i;

    CRYPTO_set_locking_callback(0);
    CRYPTO_set_dynlock_create_callback(0);
    CRYPTO_set_dynlock_lock_callback(0);
    CRYPTO_set_dynlock_destroy_callback(0);

    for (i = 0; i < CRYPTO_num_locks(); i++) {
        #if defined(_WIN32) || defined(_WIN64)
            DeleteCriticalSection(&mutex_buf[i]);
        #else
            pthread_mutex_destroy(&(mutex_buf[i]));
        #endif
    }

    ueum_safe_free(mutex_buf);
    mutex_buf = NULL;
}

bool uecm_openssl_init() {
    SSL_library_init();
    OpenSSL_add_all_algorithms();

    /* Load the strings and init the library */
    SSL_load_error_strings();

    if (!alloc_mutexes()) {
        ei_stacktrace_push_msg("Failed to alloc mutexes");
        return false;
    }

    CRYPTO_set_id_callback(openssl_id_function_callback);
    CRYPTO_set_locking_callback(openssl_locking_function_callback);

    return true;
}

void uecm_openssl_uninit() {
    RAND_cleanup();
    dealloc_mutexes();
    FIPS_mode_set(0);
    ENGINE_cleanup();
    CONF_modules_unload(1);
    EVP_cleanup();
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();

    SSL_COMP_free_compression_methods();
}
