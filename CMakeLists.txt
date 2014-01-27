project(pam_kwallet)
cmake_minimum_required(VERSION 2.8)

set(CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules" )

find_package(PAM REQUIRED)
find_package(LibGcrypt REQUIRED)

include_directories (
   ${PAM_INCLUDE_DIR}
   ${CMAKE_BINARY_DIR}
   ${CMAKE_CURRENT_BINARY_DIR}
)

set(pam_kwallet_SRCS
   pam_kwallet.c
)

add_library (pam_kwallet SHARED ${pam_kwallet_SRCS})
set_target_properties (pam_kwallet PROPERTIES PREFIX "")
target_link_libraries (pam_kwallet
   ${PAM_LIBRARIES}
   ${LIBGCRYPT_LIBRARIES}
)
