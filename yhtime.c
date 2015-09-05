#include "yhtime.h"
#include "error.h"

void maketimeout_minutes(struct timespec *tsp, long minutes)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    tsp->tv_sec  = now.tv_sec + minutes * 60;
    tsp->tv_nsec = now.tv_usec * 1000;
}
void maketimeout_seconds(struct timespec *tsp, long seconds)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    tsp->tv_sec  = now.tv_sec + seconds;
    tsp->tv_nsec = now.tv_usec * 1000;
}
void maketimeout_milliseconds(struct timespec *tsp, long millisconds)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    tsp->tv_sec  = now.tv_sec + millisconds / 1000;
    tsp->tv_nsec = now.tv_usec * 1000 + millisconds % 1000 * 1000000;
}
void maketimeout_microsecond(struct timespec *tsp, long microsecond)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    tsp->tv_sec  = now.tv_sec + microsecond / 1000000;
    tsp->tv_nsec = now.tv_usec * 1000 + microsecond % 1000000 * 1000;
}
void maketimeout_nanoseconds(struct timespec *tsp, long nanoseconds)
{
    struct timeval now;
    gettimeofday(&now, NULL);
    tsp->tv_sec  = now.tv_sec + nanoseconds / 1000000000UL;
    tsp->tv_nsec = now.tv_usec * 1000 + nanoseconds % 1000000000UL;
}

void maketimeout_min(struct timespec *tsp, long minutes)
{
    maketimeout_minutes(tsp, minutes);
}
void maketimeout_sec(struct timespec *tsp, long seconds)
{
    maketimeout_seconds(tsp, seconds);
}
void maketimeout_msec(struct timespec *tsp, long millisconds)
{
    maketimeout_milliseconds(tsp, millisconds);
}
void maketimeout_usec(struct timespec *tsp, long microsecond)
{
    maketimeout_microsecond(tsp, microsecond);
}
void maketimeout_nsec(struct timespec *tsp, long nanoseconds)
{
    maketimeout_nanoseconds(tsp, nanoseconds);
}
