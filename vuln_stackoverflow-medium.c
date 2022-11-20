#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>
#include <rpc/svc.h>
#include <rpc/rpc.h>

/**
 * Vulnerable function. Unused function parameters removed and replaced by input from stdin for exploitation
 */
void svcunix_create_vuln(char *path)
{
  bool_t madesock = FALSE;
  SVCXPRT *xprt;
  struct unix_rendezvous *r;
  struct sockaddr_un addr;
  socklen_t len = sizeof(struct sockaddr_in);

  memset(&addr, '\0', sizeof(addr));
  addr.sun_family = AF_UNIX;
  len = strlen(path) + 1;
  memcpy(addr.sun_path, path, len);
  len += sizeof(addr.sun_family);
}

int main(int argc, char **argv)
{
  if (argc > 1)
  {
    svcunix_create_vuln(argv[1]);
  }

  return 0;
}
