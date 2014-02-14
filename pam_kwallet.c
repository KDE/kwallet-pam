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
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
#define PAM_SM_AUTH
#include <pwd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <security/_pam_types.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

#define KWALLET_PAM_KEYSIZE 56
#define KWALLET_PAM_SALTSIZE 56
#define KWALLET_PAM_ITERATIONS 50000

static const char* get_env(pam_handle_t *ph, const char *name)
{
    const char *env = pam_getenv (ph, name);
    if (env && env[0]) {
        return env;
    }

    env = getenv (name);
    if (env && env[0]) {
        return env;
    }

    return NULL;
}

static int set_env(pam_handle_t *pamh, const char *name, const char *value)
{
    if (setenv(name, value, 1) < 0) {
        pam_syslog(pamh, LOG_WARNING, "pam_kwallet: Couldn't setenv %s = %s", name, value);
        //We do not return because pam_putenv might work
    }

    char *pamEnv = malloc(strlen(name) + strlen(value) + 2); //2 is for = and \0
    if (!pamEnv) {
        pam_syslog(pamh, LOG_WARNING, "pam_kwallet: Impossible to allocate memory for pamEnv");
        return -1;
    }

    sprintf(pamEnv, "%s=%s", name, value);
    printf("PAMENV %s\n", pamEnv);
    int ret = pam_putenv(pamh, pamEnv);
    free(pamEnv);

    return ret;
}

/**
 * Code copied from gkr-pam-module.c, GPL2+
 */
static void wipeString(char *str)
{
    if (!str) {
        return;
    }

    size_t len;
    volatile char *vp;

    /* Defeats some optimizations */
    len = strlen (str);
    memset (str, 0xAA, len);
    memset (str, 0xBB, len);

    /* Defeats others */
    vp = (volatile char*)str;
    while (*vp) {
        *(vp++) = 0xAA;
    }

    free (str);
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
    wipeString(password);

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

    char *key = malloc(sizeof(char) * KWALLET_PAM_KEYSIZE);
    kwallet_hash(password, username, key);

    result = pam_set_data(pamh, "kwallet_key", key, NULL);
    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: Impossible to store the hashed password: %s"
            , pam_strerror(pamh, result));
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

static void execute_kwallet(pam_handle_t *pamh, struct passwd *userInfo, int toWalletPipe[2], int envSocket)
{
    int x = 2;
    //Close fd that are not of interest of kwallet
    for (; x < 64; ++x) {
        if (x != toWalletPipe[0] && x != envSocket) {
            close (x);
        }
    }

    //This is the side of the pipe PAM will send the hash to
    close (toWalletPipe[1]);

    //Change to the user in case we are not it yet
    if (setgid (userInfo->pw_gid) < 0 || setuid (userInfo->pw_uid) < 0 ||
        setegid (userInfo->pw_gid) < 0 || seteuid (userInfo->pw_uid) < 0) {
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: could not set gid/uid/euid/egit for kwalletd");
        goto cleanup;
    }

    //TODO use a pam argument for full path kwalletd
    char pipeInt[2];
    sprintf(pipeInt, "%d", toWalletPipe[0]);
    char sockIn[2];
    sprintf(sockIn, "%d", envSocket);

    char *args[] = {"/opt/kde4/bin/kwalletd", "--pam-login", pipeInt, sockIn, NULL};
    execve(args[0], args, pam_getenvlist(pamh));
    pam_syslog(pamh, LOG_ERR, "pam_kwallet: could not execute kwalletd");

cleanup:
    exit(EXIT_FAILURE);
}

static int better_write(int fd, const char *buffer, int len)
{
    size_t writtenBytes = 0;
    size_t result;
    while(writtenBytes < len) {
        result = write(fd, buffer + writtenBytes, len - writtenBytes);
        printf("Result write %d\n", result);
        if (result < 0) {
            if (errno != EAGAIN && errno != EINTR) {
                return -1;
            }
        }
        writtenBytes += result;
    }

    return 0;
}

static void start_kwallet(pam_handle_t *pamh, struct passwd *userInfo, const char *kwalletKey)
{
    //Just in case we get broken pipe, do not break the pam process..
    struct sigaction sigPipe, oldSigPipe;
    memset (&sigPipe, 0, sizeof (sigPipe));
    memset (&oldSigPipe, 0, sizeof (oldSigPipe));
    sigPipe.sa_handler = SIG_IGN;
    sigaction (SIGPIPE, &sigPipe, &oldSigPipe);

    int toWalletPipe[3] = { -1, -1};
    if (pipe(toWalletPipe) < 0) {
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: Couldn't create pipes");
    }

    int envSocket;
    if ((envSocket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        perror("socket");
        exit(1);
    }

    struct sockaddr_un local;
    local.sun_family = AF_UNIX;
    strcpy(local.sun_path, "/tmp/test.socket");
    unlink(local.sun_path);//Just in case it exists from a previous login

    int len;
    len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(envSocket, (struct sockaddr *)&local, len) == -1) {
        fprintf(stdout, "kwalletd: Couldn't bind to local file\n");
        return /*-1*/;
    }

    if (listen(envSocket, 5) == -1) {
        fprintf(stdout, "kwalletd: Couldn't listen in socket\n");
        return /*-1*/;
    }

    pid_t pid;
    switch (pid = fork ()) {
    case -1:
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: Couldn't fork to execv kwalletd");
        return;

    //Child fork, will contain kwalletd
    case 0:
        execute_kwallet(pamh, userInfo, toWalletPipe, envSocket);
        /* Should never be reached */
        break;

    //Parent
    default:
        break;
    };

    close(toWalletPipe[0]);//Read end of the pipe, we will only use the write
    if (better_write(toWalletPipe[1], kwalletKey, KWALLET_PAM_KEYSIZE) < 0) {
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: Impossible to write walletKey to walletPipe");
        return;
    }

    close(toWalletPipe[1]);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    printf("pam_sm_open_session\n");

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

    const char *kwalletKey;
    result = pam_get_data(pamh, "kwallet_key", (const void **)&kwalletKey);

    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_INFO, "pam_kwallet: open_session called without kwallet_key");
        return PAM_IGNORE;
    }

    result = set_env(pamh, "PAM_KWALLET_LOGIN", "1");
    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "pam_kwallet: Impossible to set PAM_KWALLET_LOGIN env, %s", pam_strerror(pamh, result));
        return PAM_IGNORE;
    }

    start_kwallet(pamh, userInfo, kwalletKey);

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

static char* createNewSalt(const char *path)
{
    unlink(path);

    char *salt = gcry_random_bytes(KWALLET_PAM_SALTSIZE, GCRY_STRONG_RANDOM);
    FILE *fd = fopen(path, "w");
    fwrite(salt, KWALLET_PAM_SALTSIZE, 1, fd);
    fclose(fd);

    return salt;
}
int kwallet_hash(const char *passphrase, const char *username, char *key)
{
    if (!gcry_check_version("1.6.0")) {
        printf("libcrypt version is too old \n");
        return 1;
    }
    printf("libcrypt initialized\n");

    struct stat info;
    char *salt = NULL;
    char *path = "/home/afiestas/.kde4/share/apps/kwallet/kdewallet.salt";
    if (stat(path, &info) != 0 || info.st_size == 0) {
        salt = createNewSalt(path);
    } else {
        FILE *fd = fopen(path, "r");
        salt = (char*) malloc(sizeof(char) * KWALLET_PAM_SALTSIZE);
        memset(salt, '\0', KWALLET_PAM_SALTSIZE);
        fread(salt, KWALLET_PAM_SALTSIZE, 1, fd);
        fclose(fd);
    }

    gcry_error_t error;
    error = gcry_control(GCRYCTL_INIT_SECMEM, 32768, 0);
    if (error != 0) {
        printf("Can't get secure memory: %d\n", error);
        return;
    }
    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    error = gcry_kdf_derive(passphrase, strlen(passphrase),
                            GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                            salt, KWALLET_PAM_SALTSIZE,
                            KWALLET_PAM_ITERATIONS,KWALLET_PAM_KEYSIZE, key);
    return 0;
}