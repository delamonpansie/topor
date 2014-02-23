#include <stdio.h>
#include <stdlib.h>
#include <strings.h>

static __inline__ int
is_space(char c)
{
	if(c == ' ') return 1;
	if(c == '\t') return 1;
	return 0;
}

char*
skipspaces(char *p)
{
	while(*p) {
		if(!is_space(*p)) return p;
		p++;
	}
	return p;
}

char*
skipsymbols(char *p)
{
	while(*p) {
		if(is_space(*p)) return p;
		p++;
	}
	return p;
}

int
parseline(char *p, int *cno, char **url, size_t *bufsize)
{
	p = skipspaces(p);
	if(*p == '\0' || *p == '\n' || *p == '#') return 0;
	*cno = atoi(p);
	p = skipsymbols(p);
	p = skipspaces(p);
	if(*p == '\0') return 1;
	char *op = p;
	p = skipsymbols(p);
	*url = op;
	if(*p == '\0') return 2;
	*p = '\0';
	p = skipspaces(p);
	if(*p == '\0') return 2;
	*bufsize = atoi(p);
	return 3;
}

