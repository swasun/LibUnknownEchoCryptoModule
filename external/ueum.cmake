cmake_minimum_required(VERSION 3.5)

add_custom_target(libueum)

if (systemlib_LIBUEUM)
    if (WIN32)
        set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\include")
        set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\lib\\ueum_static.lib")
    elseif (UNIX)
        set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "-lueum")
	endif ()
else (systemlib_LIUEUM)
	set(found FALSE)

	if (UNIX)
		find_library(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES ueum)
		find_path(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR NAMES ueum)
		if (LIBUNKNOWNECHOUTILSMODULE_LIBRARIES)
			set(found TRUE)
		else ()
			set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "")
			set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "")
		endif ()
	elseif (WIN32)
		if (EXISTS "C:\\LibUnknownEchoUtilsModule\\$ENV{name}")
			set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\include")
			set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\lib\\ueum_static.lib")
		endif ()
	endif ()

	if (NOT found)
		include (ExternalProject)

		set(LIBUEUM_URL https://github.com/swasun/LibUnknownEchoUtilsModule.git)
		set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/external/libueum_archive)
		set(LIBUEUM_BUILD ${CMAKE_CURRENT_BINARY_DIR}/libueum/src/libueum)
		set(LIBUEUM_INSTALL ${CMAKE_CURRENT_BINARY_DIR}/libueum/install)

		if (WIN32)
			set(libueum_STATIC_LIBRARIES "${CMAKE_CURRENT_BINARY_DIR}\\ueum_static.lib")
		else()
			set(libueum_STATIC_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/libueum/install/lib/libueum.a)
		endif()

		ExternalProject_Add(libueum
			PREFIX libueum
			GIT_REPOSITORY ${LIBUEUM_URL}	
			BUILD_IN_SOURCE 1
			BUILD_BYPRODUCTS ${libueum_STATIC_LIBRARIES}
			DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
			CMAKE_CACHE_ARGS
				-DCMAKE_BUILD_TYPE:STRING=Release
				-DCMAKE_INSTALL_PREFIX:STRING=${LIBUEUM_INSTALL}
		)

		if (WIN32)
			set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "${CMAKE_CURRENT_BINARY_DIR}\\libueum\\install\\include")
			set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "${CMAKE_CURRENT_BINARY_DIR}\\libueum\\install\\lib\\ueum_static.lib")
		elseif (UNIX)
			set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "-lueum")
		endif ()
	endif ()
endif (systemlib_LIBUEUM)
