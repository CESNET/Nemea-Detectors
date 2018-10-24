#ifndef BLACKLISTFILTER_BLACKLIST_WATCHER_H
#define BLACKLISTFILTER_BLACKLIST_WATCHER_H

/**
* Mutex for synchronization.
*/
static pthread_mutex_t BLD_SYNC_MUTEX;

void *watch_blacklist_files(void *);

#endif //BLACKLISTFILTER_BLACKLIST_WATCHER_H
