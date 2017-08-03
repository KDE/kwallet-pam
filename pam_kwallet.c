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
#include <grp.h>

#define PAM_SM_PASSWORD
#define PAM_SM_SESSION
#define PAM_SM_AUTH
#include <pwd.h>
#include <sys/stat.h>
#include <sys/syslog.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>

/* PAM headers.
 *
 * There are three styles in play:
 *  - Apple, which has no pam_ext.h, does have pam_appl.h, does have pam_syslog
 *  - Linux, which has pam_ext.h, does have pam_appl.h, does have pam_syslog
 *  - BSD, which has no pam_ext.h, does have pam_appl.h, but no pam_syslog
 * In the latter case, #define pam_syslog away.
 */
#ifdef __APPLE__
#include "pam_darwin.h"
#include <security/pam_appl.h>
#else
#include <security/pam_modules.h>
#ifdef HAVE_PAM_EXT
/* "Linux style" */
#include <security/pam_ext.h>
#include <security/_pam_types.h>
#endif
#ifdef HAVE_PAM_APPL
/* "BSD style" .. see also __APPLE__, above */
#include <security/pam_appl.h>
#ifndef HAVE_PAM_EXT
/* FreeBSD has no pam_syslog(), va-macro it away */
#define pam_syslog(...)
#endif
#endif
#endif

#define KWALLET_PAM_KEYSIZE 56
#define KWALLET_PAM_SALTSIZE 56
#define KWALLET_PAM_ITERATIONS 50000

const static char *kdehome = NULL;
const static char *kwalletd = NULL;
const static char *socketPath = NULL;
const static char *kwalletPamDataKey = NULL;
const static char *logPrefix = NULL;

#ifdef KWALLET5
const static char *envVar = "PAM_KWALLET5_LOGIN";
#else
const static char *envVar = "PAM_KWALLET_LOGIN";
#endif

static int argumentsParsed = -1;

int kwallet_hash(const char *passphrase, struct passwd *userInfo, char *key);

static void parseArguments(int argc, const char **argv)
{
    //If already parsed
    if (argumentsParsed != -1) {
        return;
    }

    int x = 0;
    for (;x < argc; ++x) {
        if (strstr(argv[x], "kdehome=") != NULL) {
            kdehome = argv[x] + 8;
        } else if (strstr(argv[x], "kwalletd=") != NULL) {
            kwalletd = argv[x] + 9;
        } else if (strstr(argv[x], "socketPath=") != NULL) {
            socketPath= argv[x] + 11;
        }
    }
#ifdef KWALLET5
    if (kdehome == NULL) {
        kdehome = ".local/share";
    }
    if (kwalletd == NULL) {
        kwalletd = "/usr/bin/kwalletd5";
    }
    if (kwalletPamDataKey == NULL) {
        kwalletPamDataKey = "kwallet5_key";
    }
    if (logPrefix == NULL) {
        logPrefix = "pam_kwallet5";
    }
#else
    if (kdehome == NULL) {
        kdehome = ".kde";
    }
    if (kwalletd == NULL) {
        kwalletd = "/usr/bin/kwalletd";
    }
    if (kwalletPamDataKey == NULL) {
        kwalletPamDataKey = "kwallet_key";
    }
    if (logPrefix == NULL) {
        logPrefix = "pam_kwallet";
    }
#endif
}

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
        pam_syslog(pamh, LOG_WARNING, "%s: Couldn't setenv %s = %s", logPrefix, name, value);
        //We do not return because pam_putenv might work
    }

    size_t pamEnvSize = strlen(name) + strlen(value) + 2; //2 is for = and \0
    char *pamEnv = malloc(pamEnvSize);
    if (!pamEnv) {
        pam_syslog(pamh, LOG_WARNING, "%s: Impossible to allocate memory for pamEnv", logPrefix);
        return -1;
    }

    snprintf (pamEnv, pamEnvSize, "%s=%s", name, value);
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

static void cleanup_free(pam_handle_t *pamh, void *ptr, int error_status)
{
    free(ptr);
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    pam_syslog(pamh, LOG_INFO, "%s: pam_sm_authenticate\n", logPrefix);
    if (get_env(pamh, envVar) != NULL) {
        pam_syslog(pamh, LOG_INFO, "%s: we were already executed", logPrefix);
        return PAM_SUCCESS;
    }

    parseArguments(argc, argv);

    int result;

    //Fetch the user, needed to get user information
    const char *username;
    result = pam_get_user(pamh, &username, NULL);
    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "%s: Couldn't get username %s",
                   logPrefix, pam_strerror(pamh, result));
        return PAM_IGNORE;//Since we are not an essential module, just make pam ignore us
    }

    struct passwd *userInfo;
    userInfo = getpwnam(username);
    if (!userInfo) {
        pam_syslog(pamh, LOG_ERR, "%s: Couldn't get user info (passwd) info", logPrefix);
        return PAM_IGNORE;
    }

    const char *password;
    result = pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password);

    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "%s: Couldn't get password %s", logPrefix,
                   pam_strerror(pamh, result));
        return PAM_IGNORE;
    }

    if (!password) {
        pam_syslog(pamh, LOG_NOTICE, "%s: Couldn't get password (it is empty)", logPrefix);
        //Asking for the password ourselves
        result = prompt_for_password(pamh);
        if (result != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "%s: Prompt for password failed %s",
                       logPrefix, pam_strerror(pamh, result)
            );
            return PAM_IGNORE;
        }
    }

    //even though we just set it, better check to be 100% sure
    result = pam_get_item(pamh, PAM_AUTHTOK, (const void**)&password);
    if (result != PAM_SUCCESS || !password) {
        pam_syslog(pamh, LOG_ERR, "%s: Password is not there even though we set it %s", logPrefix,
                   pam_strerror(pamh, result));
        return PAM_IGNORE;
    }

    char *key = malloc(KWALLET_PAM_KEYSIZE);
    if (!key || kwallet_hash(password, userInfo, key) != 0) {
        free(key);
        pam_syslog(pamh, LOG_ERR, "%s: Fail into creating the hash", logPrefix);
        return PAM_IGNORE;
    }

    result = pam_set_data(pamh, kwalletPamDataKey, key, cleanup_free);

    if (result != PAM_SUCCESS) {
        free(key);
        pam_syslog(pamh, LOG_ERR, "%s: Impossible to store the hashed password: %s", logPrefix
            , pam_strerror(pamh, result));
        return PAM_IGNORE;
    }

    //if sm_open_session has already been called (but we did not have password), call it now
    const char *session_bit;
    result = pam_get_data(pamh, "sm_open_session", (const void **)&session_bit);
    if (result == PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "%s: open_session was called before us, calling it now", logPrefix);
        return pam_sm_open_session(pamh, flags, argc, argv);
    }

    //TODO unlock kwallet that is already executed
    return PAM_SUCCESS;
}

static void execute_kwallet(pam_handle_t *pamh, struct passwd *userInfo, int toWalletPipe[2], int envSocket)
{
    //In the child pam_syslog does not work, using syslog directly
    int x = 2;
    //Close fd that are not of interest of kwallet
    for (; x < 64; ++x) {
        if (x != toWalletPipe[0] && x != envSocket) {
            close (x);
        }
    }

    //This is the side of the pipe PAM will send the hash to
    close (toWalletPipe[1]);

    /* When dropping privileges from root, the `setgroups` call will
    * remove any extraneous groups. If we don't call this, then
    * even though our uid has dropped, we may still have groups
    * that enable us to do super-user things. This will fail if we
    * aren't root, so don't bother checking the return value, this
    * is just done as an optimistic privilege dropping function.
    */
    setgroups(0, NULL);

    //Change to the user in case we are not it yet
    if (setgid (userInfo->pw_gid) < 0 || setuid (userInfo->pw_uid) < 0 ||
        setegid (userInfo->pw_gid) < 0 || seteuid (userInfo->pw_uid) < 0) {
        syslog(LOG_ERR, "%s: could not set gid/uid/euid/egit for kwalletd", logPrefix);
        goto cleanup;
    }

    // Fork twice to daemonize kwallet
    setsid();
    pid_t pid = fork();
    if (pid != 0) {
        if (pid == -1) {
            exit(EXIT_FAILURE);
        } else {
            exit(0);
        }
    }

    //TODO use a pam argument for full path kwalletd
    char pipeInt[4];
    sprintf(pipeInt, "%d", toWalletPipe[0]);
    char sockIn[4];
    sprintf(sockIn, "%d", envSocket);

#ifdef KWALLET5
    char* extraArg = NULL;
#else
    char* extraArg = "--nofork";
#endif
    char *args[] = {strdup(kwalletd), "--pam-login", pipeInt, sockIn, extraArg, NULL};
    execve(args[0], args, pam_getenvlist(pamh));
    syslog(LOG_ERR, "%s: could not execute kwalletd from %s", logPrefix, kwalletd);

cleanup:
    exit(EXIT_FAILURE);
}

static int better_write(int fd, const char *buffer, int len)
{
    size_t writtenBytes = 0;
    while(writtenBytes < len) {
        int result = write(fd, buffer + writtenBytes, len - writtenBytes);
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

    int toWalletPipe[2] = { -1, -1};
    if (pipe(toWalletPipe) < 0) {
        pam_syslog(pamh, LOG_ERR, "%s: Couldn't create pipes", logPrefix);
    }

    int envSocket;
    if ((envSocket = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
        pam_syslog(pamh, LOG_ERR, "%s: couldn't create socket", logPrefix);
        return;
    }

#ifdef KWALLET5
    const char *socketPrefix = "kwallet5";
#else
    const char *socketPrefix = "kwallet";
#endif

    char *fullSocket = NULL;
    if (socketPath) {
        size_t needed = snprintf(NULL, 0, "%s/%s_%s%s", socketPath, socketPrefix, userInfo->pw_name, ".socket");
        needed += 1;
        fullSocket = malloc(needed);
        snprintf(fullSocket, needed, "%s/%s_%s%s", socketPath, socketPrefix, userInfo->pw_name, ".socket");
    } else {
        socketPath = get_env(pamh, "XDG_RUNTIME_DIR");
        if (socketPath) {
            size_t needed = snprintf(NULL, 0, "%s/%s%s", socketPath, socketPrefix, ".socket");
            needed += 1;
            fullSocket = malloc(needed);
            snprintf(fullSocket, needed, "%s/%s%s", socketPath, socketPrefix, ".socket");
        } else {
            size_t needed = snprintf(NULL, 0, "/tmp/%s_%s%s", socketPrefix, userInfo->pw_name, ".socket");
            needed += 1;
            fullSocket = malloc(needed);
            snprintf(fullSocket, needed, "/tmp/%s_%s%s", socketPrefix, userInfo->pw_name, ".socket");
        }
    }

    int result = set_env(pamh, envVar, fullSocket);
    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "%s: Impossible to set %s env, %s",
                   logPrefix, envVar, pam_strerror(pamh, result));
        free(fullSocket);
        return;
    }

    struct sockaddr_un local;
    local.sun_family = AF_UNIX;

    if (strlen(fullSocket) > sizeof(local.sun_path)) {
        pam_syslog(pamh, LOG_ERR, "%s: socket path %s too long to open",
                   logPrefix, fullSocket);
        free(fullSocket);
        return;
    }
    strcpy(local.sun_path, fullSocket);
    free(fullSocket);
    fullSocket = NULL;
    unlink(local.sun_path);//Just in case it exists from a previous login

    pam_syslog(pamh, LOG_INFO, "%s: final socket path: %s", logPrefix, local.sun_path);

    size_t len = strlen(local.sun_path) + sizeof(local.sun_family);
    if (bind(envSocket, (struct sockaddr *)&local, len) == -1) {
        pam_syslog(pamh, LOG_INFO, "%s-kwalletd: Couldn't bind to local file\n", logPrefix);
        return;
    }

    if (listen(envSocket, 5) == -1) {
        pam_syslog(pamh, LOG_INFO, "%s-kwalletd: Couldn't listen in socket\n", logPrefix);
        return;
    }

    if (chown(local.sun_path, userInfo->pw_uid, userInfo->pw_gid) == -1) {
        pam_syslog(pamh, LOG_INFO, "%s: Couldn't change ownership of the socket", logPrefix);
        return;
    }

    pid_t pid;
    int status;
    switch (pid = fork ()) {
    case -1:
        pam_syslog(pamh, LOG_ERR, "%s: Couldn't fork to execv kwalletd", logPrefix);
        return;

    //Child fork, will contain kwalletd
    case 0:
        execute_kwallet(pamh, userInfo, toWalletPipe, envSocket);
        /* Should never be reached */
        break;

    //Parent
    default:
        waitpid(pid, &status, 0);
        if (status != 0) {
            pam_syslog(pamh, LOG_ERR, "%s: Couldn't fork to execv kwalletd", logPrefix);
            return;
        }
        break;
    };

    close(toWalletPipe[0]);//Read end of the pipe, we will only use the write
    if (better_write(toWalletPipe[1], kwalletKey, KWALLET_PAM_KEYSIZE) < 0) {
        pam_syslog(pamh, LOG_ERR, "%s: Impossible to write walletKey to walletPipe", logPrefix);
        return;
    }

    close(toWalletPipe[1]);
}

PAM_EXTERN int pam_sm_open_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    pam_syslog(pamh, LOG_INFO, "%s: pam_sm_open_session\n", logPrefix);

    if (get_env(pamh, envVar) != NULL) {
        pam_syslog(pamh, LOG_INFO, "%s: we were already executed", logPrefix);
        return PAM_SUCCESS;
    }

    parseArguments(argc, argv);

    int result;
    result = pam_set_data(pamh, "sm_open_session", "1", NULL);
    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "%s: Impossible to store sm_open_session: %s",
                   logPrefix, pam_strerror(pamh, result));
        return PAM_IGNORE;
    }

     //Fetch the user, needed to get user information
    const char *username;
    result = pam_get_user(pamh, &username, NULL);
    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_ERR, "%s: Couldn't get username %s",
                   logPrefix, pam_strerror(pamh, result));
        return PAM_IGNORE;//Since we are not an essential module, just make pam ignore us
    }

    struct passwd *userInfo;
    userInfo = getpwnam(username);
    if (!userInfo) {
        pam_syslog(pamh, LOG_ERR, "%s: Couldn't get user info (passwd) info", logPrefix);
        return PAM_IGNORE;
    }

    const char *kwalletKey;
    result = pam_get_data(pamh, kwalletPamDataKey, (const void **)&kwalletKey);

    if (result != PAM_SUCCESS) {
        pam_syslog(pamh, LOG_INFO, "%s: open_session called without %s", logPrefix, kwalletPamDataKey);
        return PAM_SUCCESS;//We will wait for pam_sm_authenticate
    }

    start_kwallet(pamh, userInfo, kwalletKey);

    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_close_session(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    pam_syslog(pamh, LOG_INFO, "%s: pam_sm_close_session", logPrefix);
    return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    pam_syslog(pamh, LOG_INFO, "%s: pam_sm_setcred", logPrefix);
    return PAM_SUCCESS;
}


PAM_EXTERN int pam_sm_chauthtok(pam_handle_t *pamh, int flags, int argc, const char **argv)
{
    pam_syslog(pamh, LOG_INFO, "%s: pam_sm_chauthtok", logPrefix);
    return PAM_SUCCESS;
}

int mkpath(char *path, struct passwd *userInfo)
{
    struct stat sb;
    char *slash;
    int done = 0;

    slash = path;

    while (!done) {
        slash += strspn(slash, "/");
        slash += strcspn(slash, "/");

        done = (*slash == '\0');
        *slash = '\0';

        if (stat(path, &sb)) {
            if (errno != ENOENT || (mkdir(path, 0777) &&
                errno != EEXIST)) {
                syslog(LOG_ERR, "%s: Couldn't create directory: %s because: %d-%s", logPrefix, path, errno, strerror(errno));
                return (-1);
            } else {
                if (chown(path, userInfo->pw_uid, userInfo->pw_gid) == -1) {
                    syslog(LOG_INFO, "%s: Couldn't change ownership of: %s", logPrefix, path);
                }
            }
        } else if (!S_ISDIR(sb.st_mode)) {
            return (-1);
        }

        *slash = '/';
    }

    return (0);
}

static char* createNewSalt(const char *path, struct passwd *userInfo)
{
    unlink(path);//in case the file already exists

    char *dir = strdup(path);
    dir[strlen(dir) - 14] = '\0';//remove kdewallet.salt
    mkpath(dir, userInfo);//create the path in case it does not exists
    free(dir);

    char *salt = gcry_random_bytes(KWALLET_PAM_SALTSIZE, GCRY_STRONG_RANDOM);
    FILE *fd = fopen(path, "w");

    //If the file can't be created
    if (fd == NULL) {
        syslog(LOG_ERR, "%s: Couldn't open file: %s because: %d-%s", logPrefix, path, errno, strerror(errno));
        return NULL;
    }

    fwrite(salt, KWALLET_PAM_SALTSIZE, 1, fd);
    fclose(fd);

    if (chown(path, userInfo->pw_uid, userInfo->pw_gid) == -1) {
        syslog(LOG_ERR, "%s: Couldn't change ownership of the created salt file", logPrefix);
    }

    return salt;
}
int kwallet_hash(const char *passphrase, struct passwd *userInfo, char *key)
{
    if (!gcry_check_version("1.5.0")) {
        syslog(LOG_ERR, "%s-kwalletd: libcrypt version is too old", logPrefix);
        return 1;
    }

#ifdef KWALLET5
    char *fixpath = "kwalletd/kdewallet.salt";
#else
    char *fixpath = "share/apps/kwallet/kdewallet.salt";
#endif
    size_t pathSize = strlen(userInfo->pw_dir) + strlen(kdehome) + strlen(fixpath) + 3;//3 == /, / and \0
    char *path = (char*) malloc(pathSize);
    sprintf(path, "%s/%s/%s", userInfo->pw_dir, kdehome, fixpath);

    struct stat info;
    char *salt = NULL;
    if (stat(path, &info) != 0 || info.st_size == 0) {
        salt = createNewSalt(path, userInfo);
    } else {
        FILE *fd = fopen(path, "r");
        if (fd == NULL) {
            syslog(LOG_ERR, "%s: Couldn't open file: %s because: %d-%s", logPrefix, path, errno, strerror(errno));
            free(path);
            return 1;
        }
        salt = (char*) malloc(KWALLET_PAM_SALTSIZE);
        memset(salt, '\0', KWALLET_PAM_SALTSIZE);
        fread(salt, KWALLET_PAM_SALTSIZE, 1, fd);
        fclose(fd);
    }
    free(path);

    if (salt == NULL) {
        syslog(LOG_ERR, "%s-kwalletd: Couldn't create or read the salt file", logPrefix);
        return 1;
    }

    gcry_error_t error;

    error = gcry_control(GCRYCTL_INIT_SECMEM, 32768, 0);
    if (error != 0) {
        free(salt);
        syslog(LOG_ERR, "%s-kwalletd: Can't get secure memory: %d", logPrefix, error);
        return 1;
    }

    gcry_control (GCRYCTL_INITIALIZATION_FINISHED, 0);

    error = gcry_kdf_derive(passphrase, strlen(passphrase),
                            GCRY_KDF_PBKDF2, GCRY_MD_SHA512,
                            salt, KWALLET_PAM_SALTSIZE,
                            KWALLET_PAM_ITERATIONS,KWALLET_PAM_KEYSIZE, key);

    free(salt);
    return (int) error; // gcry_kdf_derive returns 0 on success
}
