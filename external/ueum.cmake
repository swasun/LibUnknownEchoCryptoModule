cmake_minimum_required(VERSION 3.8)

if (systemlib_LIBUEUM)
    if (WIN32)
        set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\include")
        set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "C:\\LibUnknownEchoUtilsModule\\$ENV{name}\\lib\\ueum_static.lib")
    elseif (UNIX)
        set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "-lei")
    endif ()
else (systemlib_LIUEUM)
	#if (not defined ${LIBUNKNOWNECHOUTILSMODULE_LIBRARIES})
	#set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "")

	if (UNIX)
		find_library(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES ei)
		find_path(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR NAMES ei)
	elseif (WIN32)
		if (EXISTS "C:\\UNKNOWNECHOUTILSMODULE\\$ENV{name}")
			set(LIBUNKNOWNECHOUTILSMODULE_INCLUDE_DIR "C:\\UNKNOWNECHOUTILSMODULE\\$ENV{name}\\include")
			set(LIBUNKNOWNECHOUTILSMODULE_LIBRARIES "C:\\UNKNOWNECHOUTILSMODULE\\$ENV{name}\\lib\\ueum_static.lib")
		endif ()
	endif ()
	#endif ()

    if (NOT ${LIBUNKNOWNECHOUTILSMODULE_LIBRARIES} MATCHES "")
		include (ExternalProject)

		set(LIBUEUM_URL https://github.com/swasun/LibUnknownEchoUtilsModule.git)
		set(libueum_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/external/libueum_archive)
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
