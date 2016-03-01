project(pam_kwallet)
cmake_minimum_required(VERSION 2.8.8)

set(PROJECT_VERSION "5.5.5")
set(PROJECT_VERSION_MAJOR 5)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules" )

find_package(PAM REQUIRED)
find_package(LibGcrypt 1.5.0 REQUIRED)
include(GNUInstallDirs)

include_directories (
   ${PAM_INCLUDE_DIR}
   ${CMAKE_BINARY_DIR}
   ${CMAKE_CURRENT_BINARY_DIR}
   ${LIBGCRYPT_INCLUDE_DIR}
)

add_definitions(-DKWALLET5)
set(library_name "pam_kwallet5")

if ("${KWALLET4}" STREQUAL "1")
    remove_definitions(-DKWALLET5)
    set(library_name "pam_kwallet")
endif()

set(pam_kwallet_SRCS
   pam_kwallet.c
)

if (APPLE)
LIST(APPEND pam_kwallet_SRCS
   pam_darwin.c
)
endif()

add_library (${library_name} SHARED ${pam_kwallet_SRCS})
set_target_properties (${library_name} PROPERTIES PREFIX "")
target_link_libraries (${library_name}
   ${PAM_LIBRARIES}
   ${LIBGCRYPT_LIBRARIES}
)

install(TARGETS ${library_name} DESTINATION ${CMAKE_INSTALL_LIBDIR}/security)
