#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

struct ta_header {
    void (*destructor)();
};

/**
 * Vulnerable function. Unused function parameters removed and replaced by input from stdin for exploitation
 */
void open_mf_pattern(char *filename)
{
  char *fname = malloc(strlen(filename));
  struct ta_header *h = malloc(sizeof(struct ta_header));

  sprintf(fname, filename);
  
  if(h->destructor)
	  h->destructor();
}

int main(int argc, char **argv)
{
  if (argc > 1)
  {
    open_mf_pattern(argv[1]);
  }

  return 0;
}
