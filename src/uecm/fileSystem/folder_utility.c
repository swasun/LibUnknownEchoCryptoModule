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

#include <uecm/fileSystem/folder_utility.h>
#include <uecm/fileSystem/file_utility.h>
#include <uecm/string/string_utility.h>
#include <uecm/string/string_builder.h>
#include <uecm/string/string_split.h>
#include <uecm/container/string_vector.h>
#include <uecm/alloc.h>

#include <ei/ei.h>

#include <string.h>
#include <errno.h>

#if defined(_WIN32) || defined(_WIN64)
    #include <Windows.h>
    #include <direct.h>
#elif defined(__unix__)
    #include <sys/types.h>
    #include <sys/stat.h>
    #include <dirent.h>
    #include <unistd.h>
#else
    #error "OS not supported"
#endif

bool uecm_is_dir_exists(const char *file_name) {
#if defined(_WIN32) || defined(_WIN64)
    DWORD dw_attrib;
#else
    DIR *dir;
#endif

#if defined(_WIN32) || defined(_WIN64)
    dw_attrib = GetFileAttributesA(file_name);
    if (dw_attrib != INVALID_FILE_ATTRIBUTES &&
        dw_attrib & FILE_ATTRIBUTE_DIRECTORY) {
        return true;
    }
#elif defined(__unix__)
    dir = opendir(file_name);
    if (dir) {
        closedir(dir);
        return true;
    }
#else
    #error "OS not supported"
#endif

    return false;
}

int uecm_count_dir_files(const char *dir_name, bool recursively) {
    char path[2048];
    int files;

    ei_check_parameter_or_return(dir_name)

#if defined(_WIN32) || defined(_WIN64)
    WIN32_FIND_DATA fd_file;
    HANDLE file_handle;
#elif defined(__unix__)
    DIR *d;
    struct dirent *dir;
    char old_path[2048];
#else
    #error "OS not supported"
#endif

    files = 0;

#if defined(__unix__)
    strcpy(old_path, dir_name);

    d = opendir(dir_name);
    if (!d) {
        ei_stacktrace_push_errno()
        return -1;
    }

    while ((dir = readdir(d)) != NULL) {

        if (strcmp(dir->d_name, ".") != 0 &&
            strcmp(dir->d_name, "..") != 0) {

            memset(path, 0, sizeof(path));
            strcat(path, old_path);
            strcat(path, "/");
            strcat(path, dir->d_name);

            if (uecm_is_file_exists(path)) {
                files++;
            }
            else if (uecm_is_dir_exists(path) && recursively) {
                files += uecm_count_dir_files(path, true);
            }
        }
    }

    closedir(d);
#elif defined(_WIN32) || defined(_WIN64)
    file_handle = NULL;

    sprintf(path, "%s\\*.*", dir_name);

    if((file_handle = FindFirstFile(path, &fd_file)) == INVALID_HANDLE_VALUE) {
        ei_stacktrace_push_msg("Failed to get first file")
        return -1;
    }

    do {
        /*
           Find first file will always return "."
           and ".." as the first two directories.
        */
        if(strcmp(fd_file.cFileName, ".") != 0 &&
           strcmp(fd_file.cFileName, "..") != 0) {

            sprintf(path, "%s\\%s", dir_name, fd_file.cFileName);

            if (uecm_is_file_exists(path)) {
                files++;
            }
            else if (fd_file.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY && recursively) {
                files += uecm_count_dir_files(path, true);
            }
        }
    }
    while(FindNextFile(file_handle, &fd_file)); /* Find the next file. */

    FindClose(&fd_file);
#else
    #error "OS not supported"
#endif

    return files;
}

char **uecm_list_directory(char *dir_name, int *files, bool recursively) {
    char **file_names, **new_folder_files, path[2048], slash;
    int i, j, files_count, new_folder_files_count;

    ei_check_parameter_or_return(dir_name)

	file_names = NULL;
    *files = 0;

#if defined(__unix__)
    DIR *d;
    struct dirent *dir;
#elif defined(_WIN32) || defined(_WIN64)
    WIN32_FIND_DATA fd_file;
    HANDLE file_handle;
#else
    #error "OS not supported"
#endif

    slash = ' ';

#if defined(__unix__)
    slash = '/';
#elif defined(_WIN32) || defined(_WIN64)
    slash = '\\';
#else
    #error "OS not supported"
#endif

    if (uecm_last_char_is(dir_name, slash)) {
        uecm_remove_last_char(dir_name);
    }

    files_count = uecm_count_dir_files(dir_name, recursively);

    if (files_count == -1) {
        ei_stacktrace_push_msg("Failed to count dir files")
        return NULL;
    } else if (files_count == 0) {
        return NULL;
    }

    i = 0;

#if defined(__unix__)
    d = opendir(dir_name);
    if (!d) {
        ei_stacktrace_push_errno()
        return NULL;
    }

    uecm_safe_alloc(file_names, char*, files_count)

    if (errno == ENOMEM || !file_names) {
        uecm_safe_free(file_names);
        closedir(d);
        return NULL;
    }

    while ((dir = readdir(d)) != NULL) {
        strcpy(path, dir_name);

        if (strcmp(dir->d_name, ".") != 0 &&
            strcmp(dir->d_name, "..") != 0) {
            strcat(path, "/");
            strcat(path, dir->d_name);


            if (uecm_is_file_exists(path)) {
                if (files_count + 1 > i) {
                    uecm_safe_realloc(file_names, char*, files_count, 1);
                }
                uecm_safe_alloc(file_names[i], char, strlen(path) + 1)
                strcpy(file_names[i], path);
                i++;
            }
            else if (uecm_is_dir_exists(path) && recursively) {
                new_folder_files = uecm_list_directory(path, &new_folder_files_count, true);
                if (new_folder_files) {
                    for (j = 0; j < new_folder_files_count; j++) {
                        if (new_folder_files[j]) {
                            if (files_count + 1 > i) {
                                uecm_safe_realloc(file_names, char*, files_count, 1);
                                /*files_count++;*/
                            }
                            uecm_safe_alloc(file_names[i], char, strlen(new_folder_files[j]) + 1)
                            strcpy(file_names[i], new_folder_files[j]);
                            i++;
                        }
                    }
                    for (j = 0; j < new_folder_files_count; j++) {
                        uecm_safe_free(new_folder_files[j]);
                    }
                    uecm_safe_free(new_folder_files);
                }
            }
        }
    }

    closedir(d);
#elif defined(_WIN32) || defined(_WIN64)
    file_handle = NULL;

    sprintf(path, "%s\\*.*", dir_name);

    file_handle = FindFirstFile(path, &fd_file);
    if (file_handle == INVALID_HANDLE_VALUE) {
        ei_stacktrace_push_msg("Failed to get first file");
        return NULL;
    }

    uecm_safe_alloc(file_names, char*, files_count)

    do {
        /*
           Find first file will always return "."
           and ".." as the first two directories.
        */
        if(strcmp(fd_file.cFileName, ".") != 0 &&
           strcmp(fd_file.cFileName, "..") != 0) {

            sprintf(path, "%s\\%s", dir_name, fd_file.cFileName);

            if (uecm_is_file_exists(path)) {
                uecm_safe_alloc(file_names[i], char, strlen(path) + 1)
                strcpy(file_names[i], path);
                i++;
            }
            /* Is the entity a file or folder ? */
            else if(fd_file.dwFileAttributes &FILE_ATTRIBUTE_DIRECTORY && recursively) {
                new_folder_files = uecm_list_directory(path, &new_folder_files_count, true);
                if (new_folder_files) {
                    for (j = 0; j < new_folder_files_count; j++) {
                        uecm_safe_alloc(file_names[i], char, strlen(new_folder_files[j]) + 1)
                        strcpy(file_names[i], new_folder_files[j]);
                        i++;
                    }
                    for (j = 0; j < new_folder_files_count; j++) {
                        uecm_safe_free(new_folder_files[j]);
                    }
                    uecm_safe_free(new_folder_files);
                }
            }
        }
    }
    while(FindNextFile(file_handle, &fd_file)); /* Find the next file. */

    FindClose(&fd_file);
#else
    #error "OS not supported"
#endif

    *files = files_count;

    return file_names;
}

char *uecm_get_current_dir() {
    char *dir;
#if defined(_WIN32) || defined(_WIN64)
    DWORD result;
    char *error_buffer;
#endif

	uecm_safe_alloc(dir, char, 1024)

#if defined(__unix__)
		if (!getcwd(dir, 1024)) {
			ei_stacktrace_push_errno();
			goto failed;
		}
	return dir;
#elif defined(_WIN32) || defined(_WIN64)
	error_buffer = NULL;
    uecm_safe_alloc(dir, char, MAX_PATH);
    result = GetModuleFileName(NULL, dir, MAX_PATH);
    if (result == ERROR_INSUFFICIENT_BUFFER) {
        ei_stacktrace_push_msg("Insufficient buffer size to copy current dir");
        goto failed;
    }
    if (GetLastError() != ERROR_SUCCESS) {
        ei_get_last_werror(error_buffer);
        ei_stacktrace_push_msg(error_buffer);
        uecm_safe_free(error_buffer);
        goto failed;
    }
    if (result < MAX_PATH) {
        uecm_safe_realloc(dir, char, MAX_PATH, result);
        return dir;
    }
#else
    #error "OS not supported"
#endif

failed:
    uecm_safe_free(dir)
    return NULL;
}

bool uecm_create_folder(const char *path_name) {
    bool result;
    uecm_string_builder *full_path;
    uecm_string_vector *paths;
    int i;

    if (uecm_is_dir_exists(path_name)) {
        ei_logger_warn("Folder at path '%s' already exists", path_name);
        return true;
    }

    result = false;
    full_path = uecm_string_builder_create();
    paths = uecm_string_vector_create_empty();
    uecm_string_split_append_one_delim(paths, path_name, "/");

    for (i = 0; i < uecm_string_vector_size(paths); i++) {
        uecm_string_builder_append_variadic(full_path, "%s/", uecm_string_vector_get(paths, i));
        if (!uecm_is_dir_exists(uecm_string_builder_get_data(full_path))) {
#if defined(__unix__)
            if (mkdir((const char *)uecm_string_builder_get_data(full_path), 0700) != 0) {
#elif defined(_WIN32) || defined(_WIN64)
            if (_mkdir((const char *)uecm_string_builder_get_data(full_path)) != 0) {
#endif
                ei_stacktrace_push_errno();
                goto clean_up;
            }
        }
    }

    result = true;

clean_up:
    uecm_string_builder_destroy(full_path);
    uecm_string_vector_destroy(paths);
    return result;
}
