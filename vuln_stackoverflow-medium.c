#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <stdbool.h>
#include "svc.h"
#include "rpc.h"
/** 
 *
 * This example shows a possible way to construct an examplary vulnerable program, where the vulnerability is based on 
 * a real-world vulnerabilty, while abstracting away from all original functionality not (strictly) necessary to 
 * understand the vulnerabilty. 
 *
 *
 * Vulnerability CVE-2018-5721 (https://www.cvedetails.com/cve/CVE-2018-5721/)
 *
 * Stackoverflow in ASUS Router Webinterface
 * Exploit described in https://www.w0lfzhang.com/2018/01/17/ASUS-router-stack-overflow-in-http-server/
 *
 * Affected Versions: until 382.1_2
 * Fixed in: 384.3, https://github.com/RMerl/asuswrt-merlin.ng/commit/5b8da38516a97fe1bb61fbe0260c4068ddca87a6?diff=split
 *
 * Sourcecode repository https://github.com/RMerl/asuswrt-merlin.ng
 *
 * Resources:
 * https://penturalabs.wordpress.com/2011/03/31/vulnerability-development-buffer-overflows-how-to-bypass-full-aslr/
 * http://www.sheepshellcode.com/blog/2015/03/24/writing-buffer-overflow-exploits-with-aslr/
 *
 * Exploitable via stdinput
 */

/*
 * #define websGetVar(wp, var, default) (get_cgi(var) ? : default)
 */

/**
 * Vulnerable function. Unused function parameters removed and replaced by input from stdin for exploitation
 */
void svcunix_create_vuln (char *path)
{
  bool_t madesock = FALSE;
  SVCXPRT *xprt;
  struct unix_rendezvous *r;
  struct sockaddr_un addr;
  socklen_t len = sizeof (struct sockaddr_in);

  memset (&addr, '\0', sizeof (addr));
  addr.sun_family = AF_UNIX;
  len = strlen (path) + 1;
  memcpy (addr.sun_path, path, len);
  len += sizeof (addr.sun_family);
}

int main(int argc, char ** argv) {
    if (argc > 1) {
     svcunix_create_vuln (argv[1]);
    }

    return 0;
}
