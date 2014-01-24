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

#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
#define PAM_SM_AUTH
#include <pwd.h>
#include <sys/syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/_pam_types.h>

static const char*
get_env (pam_handle_t *ph, const char *name)
{
    const char *env;

    env = pam_getenv (ph, name);
    if (env && env[0]) {
        return env;
    }

    env = getenv (name);
    if (env && env[0]) {
        return env;
    }

    return NULL;
}

static int prompt_for_password(pam_handle_t *pamh)
{
    int result;

    //Get the function we have to call
    const struct pam_conv *conv;
    result = pam_get_item(pamh, PAM_CONV, (const void**)&conv);
    if (result != PAM_SUCCESS) {
        return result;
    }

    //prepare the message
    struct pam_message message;
    memset (&message, 0, sizeof(message));
    message.msg_style = PAM_PROMPT_ECHO_OFF;
    message.msg = "Password: ";

    //We only need one message, but we still have to send it in an array
    const struct pam_message *msgs[1];
    msgs[0] = &message;


    //Sending the message, asking for password
    struct pam_response *response = NULL;
    memset (&response, 0, sizeof(response));
    result = (conv->conv) (1, msgs, &response, conv->appdata_ptr);
    if (result != PAM_SUCCESS) {
        goto cleanup;
    }

    //If we got no password, just return;
    if (response[0].resp == NULL) {
        result = PAM_CONV_ERR;
        goto cleanup;
    }

    //Set the password in PAM memory
    char *password = response[0].resp;
    result = pam_set_item(pamh, PAM_AUTHTOK, password);
    free(password);//TODO Make sure we actually erase this from memory

    if (result != PAM_SUCCESS) {
        goto cleanup;
    }

cleanup:
    free(response);
    return result;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    printf("pam_sm_authenticate\n");

    int result;

    //Fetch the user, needed to get user information
    const char *username;
    result = pam_get_user(pamh, &username, NULL);
    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: Couldn't get username %s",
                   pam_strerror(pamh, result));
        return PAM_IGNORE;//Since we are not an essential module, just make pam ignore us
    }

    struct passwd *userInfo;
    userInfo = getpwnam(username);
    if (!userInfo) {
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: Couldn't get user info (passwd) info");
        return PAM_IGNORE;
    }

    const char *password;
    result = pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password);

    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: Couldn't get password %s",
                   pam_strerror(pamh, result));
        return PAM_IGNORE;
    }

    if (!password) {
        pam_syslog(pamh, LOG_NOTICE, "pam_kwallet: Couldn't get password (it is empty)");
        //Asking for the password ourselves
        result = prompt_for_password(pamh);
        if (result != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "pam_kwallet: Prompt for password failed %s",
                pam_strerror(pamh, result)
            );
            return PAM_IGNORE;
        }
    }

    //even though we just set it, better check to be 100% sure
    result = pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password);
    if (result != PAM_SUCCESS || !password) {
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: Password is not there even though we set it",
                   pam_strerror(pamh, result));
        return PAM_IGNORE;
    }

    //At this point we are ready to go.
    //We check if the session has started, if not we wait for open_session
    if (!get_env(pamh, "KWALLET_SESSION_STARTED")) {
        pam_syslog(pamh, LOG_INFO, "pam_kwallet: session not started, waiting for open_session");
        return PAM_SUCCESS;
    }

    //TODO unlock kwallet that is already executed
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    printf("pam_sm_open_session\n");
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    printf("pam_sm_close_session\n");
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    printf("pam_sm_setsecred\n");
    return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    printf("pam_sm_chauthtok\n");
    return PAM_SUCCESS;
}

int kwallet_hash(const char *passphrase, const char *username, char *key, size_t keySize)
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

    error = gcry_kdf_derive(passphrase, strlen(passphrase),
                            GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                            username, strlen(username),
                            500000, keySize, key);
    return 0;
}