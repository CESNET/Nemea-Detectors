#ifndef BLACKLISTFILTER_BLACKLIST_WATCHER_H
#define BLACKLISTFILTER_BLACKLIST_WATCHER_H

#define IP_DETECT_ID 0
#define URL_DETECT_ID 1
#define DNS_DETECT_ID 2

/**
* Mutex for synchronization.
*/
static pthread_mutex_t BLD_SYNC_MUTEX;

/**
* Function for tracking changes in the detection/blacklist files.
*/
void *watch_blacklist_files(void *);


/**
* Special structure for watcher_thread to distinguish (at runltime) which detector is using it.
*/
typedef struct __attribute__ ((__packed__)) {
    uint8_t detector_type; /**< IP, URL od DNS detector ID */
    void *data;             /**< configuration of the detector to be passed to watcher_thread */
} watcher_wrapper_t;

#endif //BLACKLISTFILTER_BLACKLIST_WATCHER_H
