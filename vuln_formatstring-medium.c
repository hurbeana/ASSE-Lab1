#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

struct ta_header {
    size_t size;                // size of the user allocation
    // Invariant: parent!=NULL => prev==NULL
    struct ta_header *prev;     // siblings list (by destructor order)
    struct ta_header *next;
    // Invariant: parent==NULL || parent->child==this
    struct ta_header *child;    // points to first child
    struct ta_header *parent;   // set for _first_ child only, NULL otherwise
    void (*destructor)();
};

/**
 * Vulnerable function. Unused function parameters removed and replaced by input from stdin for exploitation
 */
void create_vuln(char *filename)
{
  char *fname = malloc(strlen(filename));
  struct ta_header *h = malloc(sizeof(struct ta_header));

  sprintf(fname, filename);
  printf("%s", fname);
  
  if(h->destructor)
	  h->destructor();
}

void wrapper(char * fname){
	create_vuln(fname);
}

int main(int argc, char **argv)
{
  if (argc > 1)
  {
    wrapper(argv[1]);
  }

  return 0;
}
