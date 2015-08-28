#ifndef __YH_ARGUMENTS_H__
#define __YH_ARGUMENTS_H__

#include "error.h"

#include <unistd.h>
#include <getopt.h>
#include <stdlib.h>

extern int port, daemond;

#ifdef __cplusplus
extern "C"
{
#endif


void arguments(int argc, char **argv);
void usage(int argc, char **argv);


#ifdef __cplusplus
}
#endif
#endif 
