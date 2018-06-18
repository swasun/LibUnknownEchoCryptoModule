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

#include <uecm/container/string_vector.h>
#include <uecm/string/string_utility.h>
#include <uecm/alloc.h>
#include <ei/ei.h>

uecm_string_vector *uecm_string_vector_create_empty() {
    uecm_string_vector *v;

    uecm_safe_alloc(v, uecm_string_vector, 1);

    v->elements = NULL;
    v->number = 0;

    return v;
}

void uecm_string_vector_clean_up(uecm_string_vector *v) {
    int i;

    if (!v) {
        return;
    }

    for (i = 0; i < v->number; i++) {
        uecm_safe_free(v->elements[i]);
    }
    uecm_safe_free(v->elements);
    v->number = 0;
}

void uecm_string_vector_destroy(uecm_string_vector *v) {
    int i;

    if (!v) {
        return;
    }

    for (i = 0; i < v->number; i++) {
        uecm_safe_free(v->elements[i]);
    }
    uecm_safe_free(v->elements);

    uecm_safe_free(v);
}

bool uecm_string_vector_append(uecm_string_vector *v, const char *new_string) {
    int i;

    ei_check_parameter_or_return(v);

    if (!v->elements) {
        uecm_safe_alloc(v->elements, char *, 1);
        v->elements[0] = uecm_string_create_from(new_string);
        v->number++;
    } else {
        for (i = 0; i < v->number; i++) {
            if (!v->elements[i]) {
                v->elements[i] = uecm_string_create_from(new_string);
                return true;
            }
        }

        uecm_safe_realloc(v->elements, char *, v->number, 1);
        v->elements[v->number] = uecm_string_create_from(new_string);
        v->number++;
    }

    return true;
}

bool uecm_string_vector_append_vector(uecm_string_vector *from, uecm_string_vector *to) {
    int i;

    ei_check_parameter_or_return(from);
    ei_check_parameter_or_return(to);

    for (i = 0; i < from->number; i++) {
        if (!uecm_string_vector_append(to, uecm_string_vector_get(from, i))) {
            return false;
        }
    }

    return true;
}

bool uecm_string_vector_remove(uecm_string_vector *v, int index) {
    if (!v) {
        return true;
    }

    if (!v->elements) {
        return true;
    }

    if (uecm_string_vector_size(v) < index) {
        ei_stacktrace_push_msg("Index out of range");
        return false;
    }

    uecm_safe_free(v->elements[index]);

    return true;
}

int uecm_string_vector_size(uecm_string_vector *v) {
    if (!v) {
        return -1;
    }

    if (!v->elements) {
        return -1;
    }

    return v->number;
}

char *uecm_string_vector_get(uecm_string_vector *v, int index) {
    ei_check_parameter_or_return(v);
    ei_check_parameter_or_return(v->elements);

    if (uecm_string_vector_size(v) < index) {
        ei_stacktrace_push_msg("Index out of range");
        return NULL;
    }

    return v->elements[index];
}

bool uecm_string_vector_is_empty(uecm_string_vector *v) {
    ei_check_parameter_or_return(v);

    return !v->elements || v->number <= 0;
}

bool uecm_string_vector_print(uecm_string_vector *v, FILE *out) {
    int i;

    ei_check_parameter_or_return(v);
    ei_check_parameter_or_return(out);

    if (uecm_string_vector_is_empty(v)) {
        return false;
    }

    for (i = 0; i < v->number; i++) {
        fprintf(out, "%s\n", v->elements[i]);
    }

    return true;
}

bool uecm_string_vector_contains(uecm_string_vector *v, char *target) {
    int i;

    ei_check_parameter_or_return(v);
    ei_check_parameter_or_return(target);

    if (v->number == 0) {
        return false;
    }

    for (i = 0; i < v->number; i++) {
        if (strcmp(v->elements[i], target) == 0) {
            return true;
        }
    }

    return false;
}
