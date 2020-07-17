/**
 * \file blacklist_watcher.cpp
 * \brief  Support file for blacklist detectors.
 * \author Filip Suster, sustefil@fit.cvut.cz
 * \date 2018
 */

/*
 * Copyright (C) 2018 CESNET
 *
 * LICENSE TERMS
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 * 3. Neither the name of the Company nor the names of its contributors
 *    may be used to endorse or promote products derived from this
 *    software without specific prior written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this
 * product may be distributed under the terms of the GNU General Public
 * License (GPL) version 2 or later, in which case the provisions
 * of the GPL apply INSTEAD OF those given above.
 *
 * This software is provided ``as is'', and any express or implied
 * warranties, including, but not limited to, the implied warranties of
 * merchantability and fitness for a particular purpose are disclaimed.
 * In no event shall the company or contributors be liable for any
 * direct, indirect, incidental, special, exemplary, or consequential
 * damages (including, but not limited to, procurement of substitute
 * goods or services; loss of use, data, or profits; or business
 * interruption) however caused and on any theory of liability, whether
 * in contract, strict liability, or tort (including negligence or
 * otherwise) arising in any way out of the use of this software, even
 * if advised of the possibility of such damage.
 *
 */


/* This code is highly inspired by this source:
   http://man7.org/linux/man-pages/man7/inotify.7.html */

#include <sys/inotify.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <poll.h>

#include "blacklist_watcher.h"

// To know the config structures
#include "ipblacklistfilter.h"
#include "urlblacklistfilter.h"
#include "dnsblacklistfilter.h"

#ifdef DEBUG
#define DBG(x) fprintf x;
#else
#define DBG(x)
#endif

extern int stop;
extern int BL_RELOAD_FLAG;

/**
 * \brief Handles inotify events occuring on the filedescriptor.
 * \param fd File descriptor to watch for events
 */
static void handle_events(int fd)
{
    /* Some systems cannot read integer variables if they are not
       properly aligned. On other systems, incorrect alignment may
       decrease performance. Hence, the buffer used for reading from
       the inotify file descriptor should have the same alignment as
       struct inotify_event. */
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));

    const struct inotify_event *event;
    ssize_t len;
    char *ptr;

    /* Loop while events can be read from inotify file descriptor. */
    while (1) {
        len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN) {
            perror("Error: Couldnt read from fd");
            stop = 1; return;
        }

        /* If the nonblocking read() found no events to read, then
           it returns -1 with errno set to EAGAIN. In that case,
           we exit the loop. */
        if (len <= 0) {
            break;
        }

        /* Loop over all events in the buffer */
        for (ptr = buf; ptr < buf + len; ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *) ptr;

            if (event->mask & IN_CLOSE_WRITE) {
                DBG((stderr, "Blacklist watcher setting a flag to reload blacklists\n"));
                pthread_mutex_lock(&BLD_SYNC_MUTEX);
                BL_RELOAD_FLAG = 1;
                pthread_mutex_unlock(&BLD_SYNC_MUTEX);
            }
        }
    }
}


/**
 * \brief Watch blacklist files for IN_CLOSE_WRITE event
 * and set appropriate flag if this file changes
 * \param arg Data passed from the detector
 */
void *watch_blacklist_files(void *arg)
{
    const char *detection_file = nullptr;
    const char *detection_file2 = nullptr;

    watcher_wrapper_t *watcher_wrapper = (watcher_wrapper_t *) arg;

    switch (watcher_wrapper->detector_type) {
        case 0:
            detection_file =  ((ip_config_t *) watcher_wrapper->data) -> ipv4_blacklist_file;
            detection_file2 = ((ip_config_t *) watcher_wrapper->data) -> ipv6_blacklist_file;
	    break;
        case 1:
            detection_file = ((url_config_t *) watcher_wrapper->data) -> blacklist_file;
	    break;
        case 2:
            detection_file = ((dns_config_t *) watcher_wrapper->data) -> blacklist_file;
	    break;
    }

    int fd, poll_num;
    int wd1, wd2;
    nfds_t nfds;
    struct pollfd fds[1];

    /* Create the file descriptor for accessing the inotify API */
    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        perror("Error: Couldnt initialize inotify");
        stop = 1; return NULL;
    }

    /* Watch the files for IN_CLOSE_WRITE event */
    wd1 = inotify_add_watch(fd, detection_file, IN_CLOSE_WRITE);

    if (detection_file2 != nullptr) {
        wd2 = inotify_add_watch(fd, detection_file2, IN_CLOSE_WRITE);
        if (wd2 == -1) {
            perror("Warning: inotify_add_watch failed for IPv6 file");
        }
    }

    if (wd1 == -1) {
        perror("Error: Cannot watch the detector file, inotify_add_watch failed");
        stop = 1; return NULL;
    }

    /* Prepare for polling */
    nfds = 1;

    fds[0].fd = fd;
    fds[0].events = POLLIN;

    DBG((stderr, "Blacklist watcher listening for changes in files %s, %s\n", detection_file, detection_file2));

    while (1) {
        poll_num = poll(fds, nfds, -1);
        if (poll_num == -1) {
            if (errno == EINTR) {
                continue;
            }

            perror("Error: Poll failure");
            stop = 1; return NULL;
        }

        if (poll_num > 0) {
            if (fds[0].revents & POLLIN) {
                /* Inotify events are available */
                handle_events(fd);
            }
        }
    }
}
