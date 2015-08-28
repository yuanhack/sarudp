#include "yharguments.h"
#include "yherror.h"

int port    = 55555;
int daemond = 0;
int optp;

static struct option opt[] = {
    {"port",   1, 0, 'p'},
    {"daemon", 0, 0, 'd'},
    {"help",   0, 0, 'h'},
    {0,0,0,0}
};
void usage(int argc, char **argv)
{
    err_msg("usage: %s [port] [option[=value]]...", argv[0]);
    err_msg("  -p, --port=number       Service port(range 1~65535), like [port]");
    err_msg("                            but the priority is higher than [port]");
    err_msg("  -d, --daemon            Daemon mode");
    err_msg("  -h, --help              Usage help");
}

void port_check(int argc, char **argv, int port, char *strport)
{
    if (port <= 0) {
        err_msg("bad parameter: port %s", strport);
        usage(argc, argv);
        exit(1);
    }
}

void arguments(int argc, char **argv)
{
    char c;
    opterr = 1;
    while ((c = getopt_long(argc,argv,"p:dh", opt, 0)) != -1) {
        switch (c) {
            case 'p': 
                port = atoi(optarg);
                port_check(argc, argv, port, optarg);
                optp = 1; 
                break;
            case 'd': 
                daemond = 1;
                break;
            case 'h': 
                usage(argc, argv);
                exit(0);
            case '?':
                err_quit("Try '%s --help' for more information.", argv[0]);
            default :
                usage(argc, argv);
                exit(1);
        }
    }
    if (optp == 0) {
        port = atoi(argv[argc-1]);
        port_check(argc, argv, port, argv[argc-1]);
        optp = 1;
    }
}

