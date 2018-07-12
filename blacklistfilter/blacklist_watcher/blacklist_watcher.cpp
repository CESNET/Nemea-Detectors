
#include <sys/inotify.h>
#include <string>
#include <cctype>
#include <algorithm>
#include <iostream>
#include <fstream>
#include <cstdlib>
#include <map>
#include <vector>
#include <stdint.h>
#include <signal.h>
#include <getopt.h>
#include <dirent.h>
#include <unistd.h>
#include <pthread.h>
#include <nemea-common/nemea-common.h>
#include <unirec/unirec.h>
#include <libtrap/trap.h>
#include <poll.h>

#include "blacklist_watcher.h"

#ifdef DEBUG
#define DBG(x) fprintf x;
#else
#define DBG(x)
#endif

using namespace std;

extern int BL_RELOAD_FLAG;
extern pthread_mutex_t BLD_SYNC_MUTEX;

static void handle_events(int fd)
{
    /* Some systems cannot read integer variables if they are not
       properly aligned. On other systems, incorrect alignment may
       decrease performance. Hence, the buffer used for reading from
       the inotify file descriptor should have the same alignment as
       struct inotify_event. */

    char buf[4096]
            __attribute__ ((aligned(__alignof__(struct inotify_event))));

    const struct inotify_event *event;
    ssize_t len;
    char *ptr;

    /* Loop while events can be read from inotify file descriptor. */

    for (;;) {
        /* Read some events. */

        len = read(fd, buf, sizeof(buf));
        if (len == -1 && errno != EAGAIN) {
            perror("read");
            exit(EXIT_FAILURE);
        }

        /* If the nonblocking read() found no events to read, then
           it returns -1 with errno set to EAGAIN. In that case,
           we exit the loop. */

        if (len <= 0)
            break;

        /* Loop over all events in the buffer */

        for (ptr = buf; ptr < buf + len;
             ptr += sizeof(struct inotify_event) + event->len) {

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


/* Watch directory with blacklist files for IN_CLOSE_WRITE event
 * and set appropriate flag if these files change */
void * watch_blacklist_files(void * arg)
{
    const char * bl_file = reinterpret_cast<string*>(arg)->c_str();
    int fd, poll_num;
    int wd; // TODO: is just one watch descriptor fine?
    nfds_t nfds;
    struct pollfd fds[1];

    /* Create the file descriptor for accessing the inotify API */

    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        perror("inotify_init1");
        exit(EXIT_FAILURE);
    }

    /* Mark directories for events
       - file was opened
       - file was closed */

    wd = inotify_add_watch(fd, bl_file, IN_CLOSE_WRITE);
    if (wd == -1) {
        fprintf(stderr, "Cannot watch '%s'\n", bl_file);
        perror("inotify_add_watch");
        exit(EXIT_FAILURE);
    }

    /* Prepare for polling */

    nfds = 1;

    /* Console input */

    fds[0].fd = fd;
    fds[0].events = POLLIN;

    /* Wait for events and/or terminal input */

    DBG((stderr, "Blacklist watcher listening for changes in file %s\n", bl_file));

    while (1) {
        poll_num = poll(fds, nfds, -1);
        if (poll_num == -1) {
            if (errno == EINTR)
                continue;
            perror("poll");
            exit(EXIT_FAILURE);
        }

        if (poll_num > 0) {
            if (fds[0].revents & POLLIN) {
                /* Inotify events are available */
                handle_events(fd);
            }
        }
    }
}