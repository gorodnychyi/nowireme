/* vim: set sw=4 ts=4 sts=4 et : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/* $Id$ */
/** @file ping_thread.c
    @brief Periodically checks in with the central auth server so the auth
    server knows the gateway is still up.  Note that this is NOT how the gateway
    detects that the central server is still up.
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
*/

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h>
#include <errno.h>

#include "../config.h"
#include "safe.h"
#include "common.h"
#include "conf.h"
#include "debug.h"
#include "ping_thread.h"
#include "util.h"
#include "centralserver.h"
#include "firewall.h"
#include "gateway.h"
#include "simple_http.h"

static void ping(void);
static void nowire(void);

/** Launches a thread that periodically checks in with the wifidog auth server to perform heartbeat function.
@param arg NULL
@todo This thread loops infinitely, need a watchdog to verify that it is still running?
*/
void
thread_ping(void *arg)
{
    pthread_cond_t cond = PTHREAD_COND_INITIALIZER;
    pthread_mutex_t cond_mutex = PTHREAD_MUTEX_INITIALIZER;
    struct timespec timeout;

    while (1) {
        /* Make sure we check the servers at the very begining */
        debug(LOG_DEBUG, "Running ping()");
        ping();

        /* Sleep for config.checkinterval seconds... */
        timeout.tv_sec = time(NULL) + config_get_config()->checkinterval;
        timeout.tv_nsec = 0;

        /* Mutex must be locked for pthread_cond_timedwait... */
        pthread_mutex_lock(&cond_mutex);

        /* Thread safe "sleep" */
        pthread_cond_timedwait(&cond, &cond_mutex, &timeout);

        /* No longer needs to be locked */
        pthread_mutex_unlock(&cond_mutex);
    }
}

/** @internal
 * This function does the actual request.
 */
static void
ping(void)
{
    void nowire(void);
    char request[MAX_BUF];
    FILE *fh;
    int sockfd;
    unsigned long int sys_uptime = 0;
    unsigned int sys_memfree = 0;
    float sys_load = 0;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();
    static int authdown = 0;

    debug(LOG_DEBUG, "Entering ping()");
    memset(request, 0, sizeof(request));

    /*
     * The ping thread does not really try to see if the auth server is actually
     * working. Merely that there is a web server listening at the port. And that
     * is done by connect_auth_server() internally.
     */
    sockfd = connect_auth_server();
    if (sockfd == -1) {
        /*
         * No auth servers for me to talk to
         */
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
        return;
    }

    /*
     * Populate uptime, memfree and load
     */
    if ((fh = fopen("/proc/uptime", "r"))) {
        if (fscanf(fh, "%lu", &sys_uptime) != 1)
            debug(LOG_CRIT, "Failed to read uptime");

        fclose(fh);
    }
    if ((fh = fopen("/proc/meminfo", "r"))) {
        while (!feof(fh)) {
            if (fscanf(fh, "MemFree: %u", &sys_memfree) == 0) {
                /* Not on this line */
                while (!feof(fh) && fgetc(fh) != '\n') ;
            } else {
                /* Found it */
                break;
            }
        }
        fclose(fh);
    }
    if ((fh = fopen("/proc/loadavg", "r"))) {
        if (fscanf(fh, "%f", &sys_load) != 1)
            debug(LOG_CRIT, "Failed to read loadavg");

        fclose(fh);
    }
    /*
     * Prep & send request
     */
    snprintf(request, sizeof(request) - 1,
             "GET %s%sgw_id=%s&sys_uptime=%lu&sys_memfree=%u&sys_load=%.2f&wifidog_uptime=%lu HTTP/1.0\r\n"
             "User-Agent: NoWireMe %s\r\n"
             "Host: %s\r\n"
             "\r\n",
             auth_server->authserv_path,
             auth_server->authserv_ping_script_path_fragment,
             config_get_config()->gw_id,
             sys_uptime,
             sys_memfree,
             sys_load,
             (long unsigned int)((long unsigned int)time(NULL) - (long unsigned int)started_time),
             VERSION, auth_server->authserv_hostname);

    char *res;
#ifdef USE_CYASSL
    if (auth_server->authserv_use_ssl) {
        res = https_get(sockfd, request, auth_server->authserv_hostname);
    } else {
        res = http_get(sockfd, request);
    }
#endif
#ifndef USE_CYASSL
    res = http_get(sockfd, request);
#endif
    if (NULL == res) {
        debug(LOG_ERR, "There was a problem pinging the auth server!");
        if (!authdown) {
            fw_set_authdown();
            authdown = 1;
        }
    } else if ((strstr(res, "Update") != 0) || (strstr(res, "Pong") !=0)) {
        debug(LOG_DEBUG, "Server says: Pong/Update");
        if (authdown) {
            fw_set_authup();
            authdown = 0;
        }
        if (strstr(res, "Update") !=0) {
        debug(LOG_DEBUG, "Starting update process");
            nowire();
        }
        free(res);
    } else {
        debug(LOG_ERR, "Auth Server alive but says bullshit");
        if (authdown) {
            fw_set_authup();
            authdown = 0;
        }
        free(res);
    }
    return;
}

/** @internal
 * This function does nowire.me actions.
 * Should run ONLI if ping() returns Update.
 */
static void
nowire(void)
{
    int sockfd;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();

    debug(LOG_DEBUG, "Nowire started()");
    
    char request[MAX_BUF];
    sockfd = connect_auth_server();
    memset(request, 0, sizeof(request));
    
    pid_t   pid;
    pid = fork();

    if (pid == 0)
        {
            snprintf(request, sizeof(request) - 1,
                     "GET %s%sreq=update&gw_id=%s HTTP/1.0\r\n"
                     "User-Agent: NoWireMe %s\r\n"
                     "Host: %s\r\n"
                     "\r\n",
                     auth_server->authserv_path,
                     auth_server->authserv_ping_script_path_fragment,
                     config_get_config()->gw_id,
                     VERSION, auth_server->authserv_hostname);
            
            // Parse output
            char *res;
            #ifdef USE_CYASSL
                if (auth_server->authserv_use_ssl) {
                    res = https_get(sockfd, request, auth_server->authserv_hostname);
                } else {
                    res = http_get(sockfd, request);
                }
            #endif
            #ifndef USE_CYASSL
                res = http_get(sockfd, request);
            #endif
                if (NULL == res) {
                    debug(LOG_ERR, "There was a problem taking update from the auth server!");
                } else {
                    debug(LOG_DEBUG, "Got update command!");
// initiate update process
                    char *htmlbody;
                    htmlbody = strstr(res, "\r\n\r\n");
                    if (htmlbody != NULL){ 
                        htmlbody += 4;
                    } else {
                        htmlbody = res;
                    }
                    free(res);

// Encode request string
                    char command[MAX_BUF];
                    char encdata[MAX_BUF];
                    FILE *fh;
                    FILE *fc;
                    fc = fopen("/tmp/runner.sh", "w");
                        fputs("#!/bin/sh\n\n", fc);
                    sprintf(command, "echo %s | openssl enc -aes-256-cbc -a -d -salt -pass pass:%s", htmlbody, config_get_config()->gw_id);
                    fh = popen(command, "r");
                        while (fgets(encdata, sizeof(encdata)-1, fh) != NULL) {
                            fputs(encdata, fc);
                        }
                    pclose(fh); 
                    fclose(fc);
            debug(LOG_DEBUG,"_______Call runner_________");
            void runner(void);
            runner();
        }
     exit(0);
 }
}
void
runner(void)
{
    char command[MAX_BUF];
    int sockfd;
    int cmdstat;
    int cmdresult;
    t_auth_serv *auth_server = NULL;
    auth_server = get_auth_server();
    
    char request[MAX_BUF];
    sockfd = connect_auth_server();
    memset(request, 0, sizeof(request));

    debug(LOG_DEBUG, "Runner started()");

    pid_t   pid;
    pid = fork();

    if (pid == 0)
        {
                    debug(LOG_DEBUG,"_______Start runner_________");
                    FILE *fr;
                    sprintf(command, "chmod +x /tmp/runner.sh; /tmp/runner.sh >/dev/null 2>&1; echo $?");
                    fr = popen(command, "r");
                    fscanf(fr, "%d", &cmdresult);
                    pclose(fr); 
                        if (cmdresult != 0) {
                            debug(LOG_ERR, "Command returned ERR: %d", cmdresult);
                            cmdstat = 1;
                            return;
                            //exit(1);
                        } else {
                            debug(LOG_DEBUG, "Result of runner: %d", cmdresult);
                            cmdstat = 0;
                        }
                    free(cmdresult);
// send status to server
                    debug(LOG_DEBUG,"_______GET request_________");
                    snprintf(request, sizeof(request) - 1,
                        "GET %s%supd=%d&gw_id=%s HTTP/1.0\r\n"
                        "User-Agent: NoWireMe %s\r\n"
                        "Host: %s\r\n"
                        "\r\n",
                        auth_server->authserv_path,
                        auth_server->authserv_ping_script_path_fragment,
                        cmdstat,
                        config_get_config()->gw_id,
                        VERSION, auth_server->authserv_hostname);

                    char *res;
                    #ifdef USE_CYASSL
                        if (auth_server->authserv_use_ssl) {
                            res = https_get(sockfd, request, auth_server->authserv_hostname);
                        } else {
                            res = http_get(sockfd, request);
                        }
                    #endif
                    #ifndef USE_CYASSL
                        res = http_get(sockfd, request);
                    #endif
                    free(res);
                    free(cmdstat);
                    free(request);
      
            }
     exit(0);
}
