#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include "topor.h"
extern SLIST_HEAD(, channel) channels;
extern struct prog_opt topor_opt;
extern struct channel *
channel_init(int cno, const char *url, size_t bufsize);
void channel_connect(struct channel *chan);

static __inline__ int
is_space(char c)
{
	if(c == ' ' || c == '\t' || c == '\n' || c == '\r') return 1;
	return 0;
}

static __inline__ int
is_digit(char c)
{
	if(c >= '0' && c <= '9') return 1;
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
	if(*p == '\0' || *p =='\r' || *p == '\n' || *p == '#') return 0;
	if(is_digit(*p)) {
		*cno = atoi(p);
		p = skipsymbols(p);
		p = skipspaces(p);
	}
	if(*p == '\0') return 1;
	char *op = p;
	p = skipsymbols(p);
	*url = op;
	if(*p == '\0') return 2;
	op = p;
	p = skipspaces(p);
	*op = '\0';
	if(*p == '\0') return 2;
	*bufsize = atoi(p);
	return 3;
}

int
parse_config(FILE *fd)
{
	char buf[1025];
	int r, i=0, cno=1;
	size_t bufsize;
	char *churl;
	struct channel *ch;
	while(!feof(fd)) {
		fgets(buf, sizeof(buf)-1, fd);
		++i;
		bufsize = 0;
		r = parseline(buf, &cno, &churl, &bufsize);
		if(0 == r) continue;
		if(1 == r) {
			fprintf(stderr,"No channel url on line %d\n",i);
			continue;
		}
		ch = channel_init(cno, churl, bufsize);
		if(ch == NULL) return 0; //FIXME
		if(topor_opt.is_immediate) channel_connect(ch);
		cno++;
	}
	return 1;
}
