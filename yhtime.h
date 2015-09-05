#ifndef __YH_YHTIME_H__
#define __YH_YHTIME_H__

#include <sys/time.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

#pragma pack(push)
#pragma pack(1)
#pragma pack(pop)

    void maketimeout_minutes(struct timespec *tsp, long minutes);
    void maketimeout_seconds(struct timespec *tsp, long seconds);
    void maketimeout_milliseconds(struct timespec *tsp, long millisconds);
    void maketimeout_microsecond(struct timespec *tsp, long microsecond);
    void maketimeout_nanoseconds(struct timespec *tsp, long nanoseconds);

    void maketimeout_min(struct timespec *tsp, long minutes);
    void maketimeout_sec(struct timespec *tsp, long seconds);
    void maketimeout_msec(struct timespec *tsp, long millisconds);
    void maketimeout_usec(struct timespec *tsp, long microsecond);
    void maketimeout_nsec(struct timespec *tsp, long nanoseconds);

#ifdef __cplusplus
}
#endif
#endif /* __YH_YHTIME_H__ */
