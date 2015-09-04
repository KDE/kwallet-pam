/*************************************************************************************
 *  Copyright (C) 2015 by Samuel Gaist <samuel.gaist@edeltech.ch                     *
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

#include "pam_darwin.h"

#include <stdlib.h>
#include <stdio.h>
#include <sys/syslog.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

void pam_vsyslog(const pam_handle_t *ph, int priority, const char *fmt, va_list args)
{
    char *msg = NULL;
    const char *service = NULL;
    int retval;

    retval = pam_get_item(ph, PAM_SERVICE, (const void **) &service);
    if (retval != PAM_SUCCESS)
        service = NULL;
    if (vasprintf(&msg, fmt, args) < 0) {
        syslog(LOG_CRIT | LOG_AUTHPRIV, "cannot allocate memory in vasprintf: %m");
        return;
    }
    syslog(priority | LOG_AUTHPRIV, "%s%s%s: %s",
           (service == NULL) ? "" : "(",
           (service == NULL) ? "" : service,
           (service == NULL) ? "" : ")", msg);
    free(msg);
}

void pam_syslog(const pam_handle_t *ph, int priority, const char *fmt, ...)
{
    va_list args;

    va_start(args, fmt);
    pam_vsyslog(ph, priority, fmt, args);
    va_end(args);
}
