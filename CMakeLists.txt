project(pam_kwallet)
cmake_minimum_required(VERSION 3.16)
set(KF5_MIN_VERSION "5.102.0")
set(KDE_COMPILERSETTINGS_LEVEL "5.82")
set(PROJECT_VERSION "5.27.2")
set(PROJECT_VERSION_MAJOR 5)

find_package (ECM ${KF5_MIN_VERSION} REQUIRED NO_MODULE)
set (CMAKE_MODULE_PATH ${ECM_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules" )

include(CheckFunctionExists)
include(KDEInstallDirs)
include(KDEClangFormat)
include(ECMConfiguredInstall)

find_package(PAM REQUIRED)
find_package(LibGcrypt 1.5.0 REQUIRED)

find_program(SOCAT_EXECUTABLE socat)

if (SOCAT_EXECUTABLE)
  message (STATUS "Found socat executable: ${SOCAT_EXECUTABLE}")
else ()
  message (WARNING "socat is required for pam_kwallet to work")
endif ()

include_directories (
   ${PAM_INCLUDE_DIR}
   ${CMAKE_BINARY_DIR}
   ${CMAKE_CURRENT_BINARY_DIR}
   ${LIBGCRYPT_INCLUDE_DIR}
)

add_definitions(-DQT_DISABLE_DEPRECATED_BEFORE=0x050c00)
add_definitions(-DKF_DISABLE_DEPRECATED_BEFORE_AND_AT=0x054200)

set(library_name "pam_kwallet5")

set(pam_kwallet_SRCS
   pam_kwallet.c
)

find_package(KF5 ${KF5_MIN_VERSION} REQUIRED COMPONENTS
    Wallet
)

add_definitions(-DKWALLETD_BIN_PATH="${KWALLETD_BIN_PATH}")

if (APPLE)
LIST(APPEND pam_kwallet_SRCS
   pam_darwin.c
)
endif()

# Handle different PAM header styles:
#  - "Linux style" has pam_ext.h
#  - "BSD style" has pam_appl.h
#
find_file(PAM_EXT_PATH security/pam_ext.h)
find_file(PAM_APPL_PATH security/pam_appl.h)
if (PAM_EXT_PATH)
    add_definitions(-DHAVE_PAM_EXT)
endif()
if (PAM_APPL_PATH)
    add_definitions(-DHAVE_PAM_APPL)
endif()

set(CMAKE_REQUIRED_INCLUDES "string.h")
check_function_exists(explicit_bzero HAVE_EXPLICIT_BZERO)
set(CMAKE_REQUIRED_INCLUDES)

if (HAVE_EXPLICIT_BZERO)
    add_definitions(-DHAVE_EXPLICIT_BZERO)
endif()

add_library (${library_name} SHARED ${pam_kwallet_SRCS})
set_target_properties (${library_name} PROPERTIES PREFIX "")
target_link_libraries (${library_name}
   ${PAM_LIBRARIES}
   ${LIBGCRYPT_LIBRARIES}
)

# add clang-format target for all our real source files
file(GLOB_RECURSE ALL_CLANG_FORMAT_SOURCE_FILES *.cpp *.h)
kde_clang_format(${ALL_CLANG_FORMAT_SOURCE_FILES})

install(TARGETS ${library_name} DESTINATION ${KDE_INSTALL_LIBDIR}/security)

configure_file(pam_kwallet_init.desktop.cmake ${CMAKE_BINARY_DIR}/pam_kwallet_init.desktop)

install(PROGRAMS pam_kwallet_init DESTINATION ${KDE_INSTALL_LIBEXECDIR})

install(FILES ${CMAKE_BINARY_DIR}/pam_kwallet_init.desktop DESTINATION ${KDE_INSTALL_AUTOSTARTDIR})

ecm_install_configured_files(INPUT plasma-kwallet-pam.service.in @ONLY DESTINATION
        ${KDE_INSTALL_SYSTEMDUSERUNITDIR})
