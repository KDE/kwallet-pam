/*************************************************************************************
 *  Copyright (C) 2014 by Alejandro Fiestas Olivares <afiestas@kde.org>              *
 *                                                                                   *
 *  This library is free software; you can redistribute it and/or                    *
 *  modify it under the terms of the GNU Lesser General Public                       *
 *  License as published by the Free Software Foundation; either                     *
 *  version 2.1 of the License, or (at your option) any later version.               *
 *                                                                                   *
 *  This library is distributed in the hope that it will be useful,                  *
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of                   *
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU                *
 *  Lesser General Public License for more details.                                  *
 *                                                                                   *
 *  You should have received a copy of the GNU Lesser General Public                 *
 *  License along with this library; if not, write to the Free Software              *
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA       *
 *************************************************************************************/

#include <gcrypt.h>
#include <stdio.h>

int main(int argc, char **argv)
{
    if (!gcry_check_version("1.6.0"))
    {
        printf("libcrypt version is too old \n");
        return 1;
    }
    printf("libcrypt initialized\n");

    gcry_error_t error;
    error = gcry_control(GCRYCTL_INIT_SECMEM, 32768, 0);
    if (error != 0) {
        printf("Can't get secure memory: %d\n", error);
        return;
    }
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    const char *passphrase = "visheshisanubplayingmduel";
    const char *salt = "afiestas";
    char key[16];
    error = gcry_kdf_derive(passphrase, strlen(passphrase), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt), 500000, sizeof key, key);
    printf("key: %d\n", error);
    return 0;
}