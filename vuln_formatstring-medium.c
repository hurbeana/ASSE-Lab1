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
void create_vuln(char *filename)
{
  int count = 0;
  char *fname = talloc_size(mf, strlen(filename) + 32);

  sprintf(fname, filename, count++);
}

int main(int argc, char **argv)
{
  if (argc > 1)
  {
    create_vuln(argv[1]);
  }

  return 0;
}
