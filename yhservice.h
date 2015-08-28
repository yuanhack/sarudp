#ifndef __YH__HOME_HONG_PROJECT_YHEVENTS_SERVICE_H__
#define __YH__HOME_HONG_PROJECT_YHEVENTS_SERVICE_H__

#include <stdio.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>

#include "yhevent.h"


#ifdef __cplusplus
extern "C"
{
#endif

void peer_data_in(fd_event_t * fe);

#ifdef __cplusplus
}
#endif
#endif /* __YH__HOME_HONG_PROJECT_YHEVENTS_SERVICE_H__ */
