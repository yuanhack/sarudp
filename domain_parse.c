#include "domain_parse.h"

int domain_parse(const char *str, char *buff, int len, char *errinfo, int errlen)
{
    struct addrinfo *answer, hint, *curr;
    bzero(&hint, sizeof(hint));
    hint.ai_family = AF_INET;
    hint.ai_socktype = SOCK_STREAM;

    memset(errinfo, 0, errlen);

    int ret = getaddrinfo(str, NULL, &hint, &answer);
    if (ret != 0) {
        snprintf(errinfo, errlen, "getaddrinfo() %s: %s", str, gai_strerror(ret));
        return -1;
    }

    for (curr = answer; curr != NULL; curr = curr->ai_next) {
        if (!inet_ntop(AF_INET, &(((struct sockaddr_in *)(curr->ai_addr))->sin_addr), buff, len)) {
            snprintf(errinfo, errlen, "inet_ntop() error: %s", strerror(errno));
            freeaddrinfo(answer);
            return -1;
        }
        break;
    }
    freeaddrinfo(answer);
    return 0;
}

