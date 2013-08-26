/*-
 * Copyright (c) 2006 Verdens Gang AS
 * Copyright (c) 2006-2011 Varnish Software AS
 * All rights reserved.
 *
 * Author: Poul-Henning Kamp <phk@phk.freebsd.dk>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Log tailer for Varnish
 */

#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include "compat/daemon.h"

#include "vsb.h"
#include "vpf.h"

#include "libvarnish.h"
#include "vsl.h"
#include "varnishapi.h"

static int	b_flag, c_flag, s_flag = 0;

/* Ordering-----------------------------------------------------------*/

static struct vsb	*ob[65536];
static unsigned char	flg[65536];
static enum VSL_tag_e   last[65536];
static uint64_t       bitmap[65536];
#define F_INVCL		(1 << 0)

/* Validation--------------------------------------------------------*/
int isnum(char *str)
{
	int i, len;
	len = strlen(str);
	if (len < 1 || !str)
		return 0;
	
	for(i = 0; str[i] && i < len; i++)
		if (!isdigit(str[i])) {
			return 0;
		}

	return 1;
}

int isurl(char *str)
{
  int len = strlen(str);
  if (len < 1)
    return 0;

  return str[0] == '/';
}

int ishost(char *str)
{
  int len = strlen(str);
  if (len < 2 || len > 255 || strstr(str, "..")) {
    return 0;
  }
  if (strchr(str, '.') && !strchr(str, '/'))
    return 1;

  return 0;
}

char *ltrim(char *str)
{
  int i;
  if (!str)
    return 0;
  for (i = 0; *str == ' '; i++)
    str++;

  return str;
}

char *rtrim(char *str)
{
    int i;
    if (!str)
      return 0;

    for (i = strlen(str)-1; i > 0; i--)
      if (str[i] == ' ')
        str[i] = '\0';
      else
        break;

    return str;
}

int isip(char *str)
{
  int dots = 0, nums = 0;
  int i, status = 0;
  int digit = 1, dot = 0;

  int len = strlen(str);

  for (i = 0; i < len; i++) {
    if (!isdigit(str[i]) && str[i] != '.')
      break;
    if (digit) {
      if (!isdigit(str[i]))
          break;
      digit = 0;
      nums++;
    }
    if (str[i] == '.') {
      dots++;
      digit = 1;
    }
  }

  if (i == len && dots == 3 && nums == 4)
    status = 1;

  return status;
}

int isport(char *str)
{
	return isnum(str);
}

/* Hash table------------------------------------------------------*/
/* Backend name -> IP:Port 																				 */
struct nlist {
	struct nlist *next;
	char *name;
	char *defn;
};

#define HASHSIZE 1031

static struct nlist *hashtab[HASHSIZE];

unsigned hash(char *s)
{
	unsigned hashval;

	if (!s)
		return NULL;

	for (hashval = 0; *s != '\0'; s++)
		hashval = *s + 31 * hashval;

	return hashval % HASHSIZE;
}

struct nlist *nlookup(char *s)
{
	struct nlist *np;

	if (!s)
		return NULL;

	for (np = hashtab[hash(s)]; np != NULL; np = np->next)
		if (strcmp(s, np->name) == 0)
			return np;

	return NULL;
}

char *lookup(char *s)
{
	struct nlist *np;

	if (!s)
		return NULL;

	np = nlookup(s);
	if (np)
		return np->defn;

	return NULL;
}

void unlink_n(struct nlist *vp, char *s)
{
	struct nlist *np;

	if (!s || !vp)
		return;

	unsigned hashval = hash(s);

	if (vp == hashtab[hashval])
		hashtab[hashval] = vp->next;
	else {
		for (np = hashtab[hashval]; np->next != NULL; np = np->next)
			if (np->next == vp) {
				np->next = vp->next;
			}
	}
}

struct nlist *install(char *name, char *defn)
{
	struct nlist *np;
	unsigned hashval;

	if (!name)
		return NULL;

	if ((np = nlookup(name)) == NULL) {
		np = (struct nlist *)calloc(1, sizeof(*np));
		if (np == NULL || (np->name = strdup(name)) == NULL)
			return NULL;
		hashval = hash(name);
		np->next = hashtab[hashval];
		hashtab[hashval] = np;
	} else {
		free((void *)np->defn);
	}
	if ((np->defn = strdup(defn)) == NULL)
		return NULL;

	return np;
}

void uninstall(char *name)
{
	struct nlist *np;

	if (!name)
		return;

	if ((np = nlookup(name))) {
		unlink_n(np, name);

		free((void *)np->name);
		free((void *)np->defn);
		free((void *)np);
	}
}

/* JSON string------------------------------------------------------*/
char *makestr_ip(char *ip, char *port)
{
	char *str = NULL;

	if (!ip || !port)
		return NULL;

	str = (char *)calloc(strlen(ip) + strlen(port) + 2, sizeof(char));
	if (!str)
		return NULL;

	strncat(str, ip, strlen(ip));
	strncat(str, ":", 1);
	strncat(str, port, strlen(port));

	return str;
}

char *makestr_json( char *bend, char *host, 
										char *req, char *stat, 
										char *when, char *latency)
{
	char *json = NULL;
	char *ipport = NULL;
	int len = 0;

	ipport = lookup(bend);
	if (!ipport) 
		ipport = "0.0.0.0:0";

	if (ipport && host && req && stat && when && latency) {
		len = strlen(ipport) + strlen(host) + strlen(req) + strlen(stat) + strlen(when) + strlen(latency);
		len += 64; 		/* for json format */
		json = (char *)calloc(len, sizeof(char));

		/* "ip:port:vhost:req:stat": {"when": "1347955019", "latency": "27.619362"} */
		strncat(json, "{\"", 2);
		strncat(json, ipport, strlen(ipport));
		strncat(json, ":", 1);
		strncat(json, host, strlen(host));
		strncat(json, ":", 1);
		strncat(json, req, strlen(req));
		strncat(json, ":", 1);
		strncat(json, stat, strlen(stat));
		strncat(json, "\":{", 3);
		strncat(json, "\"when\":\"", 8);
		strncat(json, when, strlen(when));
		strncat(json, "\",\"latency\":\"", 13);
		strncat(json, latency, strlen(latency));
		strncat(json, "\"}}\n", 4);
	}

	return json;
}

/* FIFO-------------------------------------------------------------*/
#define FIFO_FILE	"/home/ubuntu/fifo"

static int 	fifo;

int makefifo(char *name)
{
	if (mknod(name, S_IFIFO|0666, 0) == -1)
		return -1;

	return 0;
}

int openfifo(char *name)
{
	if ((fifo = open(name, O_WRONLY)) == -1) {
		if (errno == ENOENT) {
			if (makefifo(name) != -1)
				fifo = open(name, O_WRONLY);
		}
		return fifo;
	}

	return 0;
}

int writefifo(char *json)
{
	int count = 0;

	if (fifo > 0)
		count = write(fifo, json, strlen(json));

	return count;
}

/* Parsing-------------------------------------------------------------*/
/* 	
		41 ~ 10.80.106.67 55799 248627164
		15 ~ GET
		18 ~ /
		19 ~ HTTP/1.0
		20 ~ Connection: Keep-Alive
		20 ~ Host:hello.jihoon.bst-dev.samsungpaas.com
		20 ~ User-Agent: ApacheBench/2.3
		...
	ptr  = "15 ~ GET
					48 ~ /apps/3608
					48 ~ bst-dev.samsungcloud.org
					12 ~ 25 backend0 backend0[1]
					23 ~ 200"
	line = "12 ~ 25 backend0 backend0[1]"
	word = "25 backend0 backend0[1]"
	tok  = "25", "backend0", "backend0[1]"

	varnishlog -x Length,TxHeader,TxResponse,ObjHeader,ObjResponse,ObjProtocol,RxHeader,RxResponse,SessionOpen,SessionClose,StatSess,ReqStart,RxProtocol,TxProtocol,Fetch_Body,TxRequest,RxURL,TxURL,VCL_call,VCL_return,TTL,RxStatus
*/
#define REQEND_START	1
#define REQEND_END		2
#define BACKENDOPEN_NAME	0
#define BACKENDOPEN_IP		3
#define BACKENDOPEN_PORT	4
#define BACKEND_NAME 	2

int do_parse(int tag, char *ptr)
{
  char *sepn = "\n";
  char *sepc = "~";
  char *seps = " ";
  char *line, *word, *brkt, *brkb, *tok;		/* for strtok() */

  int sol = 0; 		/* start of line */

  char *url, *host, *latency, *when, *req, *stat, *bend;	/* attrs from client request */
  char *ip = NULL, *port = NULL;													/* attrs from backend request */
  int i = 0;
  double start = 0.0, end = 0.0, delay = 0.0;

  char *ipport = NULL;
  char *json = NULL;

  char *stri = NULL;			/* for string indexing */

  url = host = latency = when = req = stat = ip = port = bend = NULL;

	if (!ptr)
	  	return 0;

  for (line = strtok_r(ptr, sepn, &brkt); 
  	line; 
  	line = strtok_r(NULL, sepn, &brkt)) 
  {
  	int hdr_tag = -1;
  	sol = 1;			/* Start of line */
  	
  	for (word = strtok_r(line, sepc, &brkb); 
    	word; 
    	word = strtok_r(NULL, sepc, &brkb))
    {
    	/* If it is 'start of line', just extract tag and continue */
    	if (sol) {
    		hdr_tag = atoi(word);
    		sol = 0;
    		if (!hdr_tag)
    			break;
    		else 
    			continue; 	/* continue to next word */
    	}

    	word = ltrim(word);		/* trim spaces by left */

    	/* Backend request */
    	if (tag == SLT_BackendClose || tag == SLT_BackendReuse) {
	    	switch (hdr_tag) {

	    		/* Extraction: backend name, ip, port */ 
	    		/* (BackendOpen) backend139[0] 10.80.106.67 55217 10.114.250.174 53427 */
	    		case SLT_BackendOpen:
	    			for (i = 0, tok = strtok(word, seps); tok; i++, tok = strtok(NULL, seps)) {
	    				if (i == BACKENDOPEN_NAME) {
	    					bend = (char*)calloc(strlen(tok)+1, sizeof(char));
	    					if (!bend)
	    						goto cleanup;

	    					strncpy(bend, tok, strlen(tok));
	    				}
	    				else if (i == BACKENDOPEN_IP) {
	    					ip = (char*)calloc(strlen(tok)+1, sizeof(char));
	    					if (!ip)
	    						goto cleanup;
	    					if (isip(tok))
	    						strncpy(ip, tok, strlen(tok));
	    					else
	    						strncpy(ip, "0.0.0.0", 8);
	    				}	    					
	    				else if (i == BACKENDOPEN_PORT) {
	    					port = (char*)calloc(strlen(tok)+1, sizeof(char));
	    					if (!port)
	    						goto cleanup;

	    					if (isport(tok))
	    						strncpy(port, tok, strlen(tok));
	    					else
	    						strncpy(port, "0", 2);
	    				}
	    			}	    		

	    			if (bend && ip && port) {
	    				if ((ipport = makestr_ip(ip, port)) != NULL)
		    				install(bend, ipport);		/* install backend ip:port to hash table */
	    			}
	    			break;

	    		/* Extraction: backend name */
	    		/* (BackendClose) backend129[0] */
	    		case SLT_BackendClose:
	    			if (!ip && !port)
	    				uninstall(word);		/* uninstall backend name from hash table */
	    			break;

	    		case SLT_TxHeader:
	  			case SLT_BackendReuse:
	    		default:
    				break;
	    	}
	    }
	    /* Client request */
	    else if (tag == SLT_ReqEnd) {
	    	switch (hdr_tag) {

	    		/* Extraction: when, latency */
	    		/* (ReqEnd) 247107527 1347723146.607604504 1347723147.188912392 0.000034094 0.581259489 0.000048399 */
	    		case SLT_ReqEnd:
	    			/* word : "248134677 1347858079.496037960 1347858079.496867180 0.000708580 0.000803709 0.000025511" */
	    			for (i = 0, tok = strtok(word, seps); tok; i++, tok = strtok(NULL, seps)) {
	    				if (i == REQEND_START)
	    					start = atof(tok);
	    				else if (i == REQEND_END) {
	    					end = atof(tok);
	    					when = (char*)calloc(strlen(tok)+1, sizeof(char));
	    					if (!when)
	    						goto cleanup;

	    					strncpy(when, tok, strlen(tok));
	    					
	    					/* when : "1347858079.496867180" */
	    					/* get largest integral value as string */
	    					stri = strchr(when, '.');
	    					*stri = '\0';

	    					break;
	    				}	    					
	    			}
	    			delay = (end - start) * 1000.0;		/* get milliseconds */

	    			latency = (char*)calloc(strlen(tok)+1, sizeof(char));
	    			if (!latency)
    					goto cleanup;

	    			sprintf(latency, "%lf", delay);
	    			break;
	    		
	    		/* Extraction: request type */
	    		/* (RxRequest) GET      */
	    		case SLT_RxRequest:
	    			req = (char*)calloc(strlen(word)+1, sizeof(char));
    				if (!req)
    					goto cleanup;

    				strncpy(req, word, strlen(word));
	    			break;

	    		/* Extraction: response code */
	    		/* (TxStatus) 200   */
	    		case SLT_TxStatus:
	    			stat = (char*)calloc(strlen(word)+1, sizeof(char));
    				if (!stat)
    					goto cleanup;

    				strncpy(stat, word, strlen(word));
	    			break;
	    		
	    		/* Extraction: URL, host name */
	    		/* (Hash) redisapp2.youly.bst-dev.samsungpaas.com  */
	    		case SLT_Hash:
	    			if (isurl(word)) {
	    				url = (char*)calloc(strlen(word)+1, sizeof(char));
	    				if (!url)
	    					goto cleanup;

	    				strncpy(url, word, strlen(word));
	    			}
	    			else if (ishost(word)) {
	    				host = (char*)calloc(strlen(word)+1, sizeof(char));
	    				if (!host)
	    					goto cleanup;

	    				strncpy(host, word, strlen(word));	
	    			}
	    			break;

	    		/* Extraction: Cached or not */
	    		/* (Hit) 247108479  */
	    		case SLT_Hit:
	  				if (!isnum(word))
	  					goto cleanup;
	  				bend = (char*)calloc(7, sizeof(char));
	  				strncpy(bend, "cached", 7); 
	  				break;

	  			/* Extraction: backend name */
	  			/* (Backend) 292 backend139 backend139[0] */
	    		case SLT_Backend:
	    			for (i = 0, tok = strtok(word, seps); tok; i++, tok = strtok(NULL, seps)) {
	    				if (i == BACKEND_NAME) {
	    					bend = (char*)calloc(strlen(tok)+1, sizeof(char));
	    					if (!bend)
	    						goto cleanup;

	    					strncpy(bend, tok, strlen(tok));
	    				}
	    			}	
	    			break;

	  			case SLT_RxHeader:
	    		case SLT_TxHeader:
					case SLT_RxStatus:

	    		default:
	    			break;
	    	}
	    }	
    }
  }

#ifdef __DEBUG
	if (tag == SLT_BackendClose || tag == SLT_BackendReuse)
		printf("Backend: %s %s:%s\n", bend, ip, port);
	else if (tag == SLT_ReqEnd) 
		printf("Client: %s %s %s %s %s %s %s\n", lookup(bend), host, url, req, stat, when, latency);     
#endif 

	if (tag == SLT_ReqEnd) {
  	json = makestr_json(bend, host, req, stat, when, latency);
  	if (json) {
  		/* FIFO mode or stdout */
  		if (s_flag)
  			writefifo(json);
  		else
  			printf("%s\n", json);
  	}
  }

cleanup:
  if (url)
  	free(url);
  if (host)
  	free(host);
  if (latency)
  	free(latency);
 	if (when)
 		free(when);
 	if (req)
 		free(req);
 	if (stat)
 		free(stat);
 	if (ip)
 		free(ip);
 	if (port)
 		free(port);
 	if (bend)
 		free(bend);
 	if (ipport)
 		free(ipport);
 	if (json)
 		free(json);
 	if (line)
 		free(line);
 	if (word)
 		free(word);

 	return 0;
}

int do_filter(int fd, struct vsb *s)
{
  char *buf = NULL;

  if (!s->s_buf)
      return -1;

  buf = (char*)malloc(s->s_size);
  if (!buf)
    return -1;

  memcpy(buf, s->s_buf, s->s_size);

#ifdef __DEBUG
  printf("START:\n %s END\n", s->s_buf);
  printf("LAST: %s\n", VSL_tags[last[fd]]);
#endif

  do_parse(last[fd], buf);

  if (buf)
    free(buf);

  return 0;
}

static void
h_order_finish(int fd, const struct VSM_data *vd)
{

	AZ(VSB_finish(ob[fd]));

	if (VSB_len(ob[fd]) > 1 && VSL_Matched(vd, bitmap[fd]))
		do_filter(fd, ob[fd]);
	bitmap[fd] = 0;

	VSB_clear(ob[fd]);
}

static void
clean_order(const struct VSM_data *vd)
{
	unsigned u;

	for (u = 0; u < 65536; u++) {
		if (ob[u] == NULL)
			continue;
		AZ(VSB_finish(ob[u]));
		if (VSB_len(ob[u]) > 1 && VSL_Matched(vd, bitmap[u])) {
			printf("%s\n", VSB_data(ob[u]));
		}
		flg[u] = 0;
		bitmap[u] = 0;
		VSB_clear(ob[u]);
	}
}

static int
h_order(void *priv, enum VSL_tag_e tag, unsigned fd, unsigned len,
    unsigned spec, const char *ptr, uint64_t bm)
{
	char type;

	struct VSM_data *vd = priv;

	/* XXX: Just ignore any fd not inside the bitmap */
	if (fd >= sizeof bitmap / sizeof bitmap[0])
		return (0);

	bitmap[fd] |= bm;

	type = (spec & VSL_S_CLIENT) ? 'c' :
	    (spec & VSL_S_BACKEND) ? 'b' : '-';

	if (!(spec & (VSL_S_CLIENT|VSL_S_BACKEND))) {
		if (!b_flag && !c_flag)
			(void)VSL_H_Print(stdout, tag, fd, len, spec, ptr, bm);
		return (0);
	}
	if (ob[fd] == NULL) {
		ob[fd] = VSB_new_auto();
		assert(ob[fd] != NULL);
	}
	if ((tag == SLT_BackendOpen || tag == SLT_SessionOpen ||
		(tag == SLT_ReqStart &&
		    last[fd] != SLT_SessionOpen &&
		    last[fd] != SLT_VCL_acl) ||
		(tag == SLT_BackendXID &&
		    last[fd] != SLT_BackendOpen)) &&
	    VSB_len(ob[fd]) != 0) {
		/*
		 * This is the start of a new request, yet we haven't seen
		 * the end of the previous one.  Spit it out anyway before
		 * starting on the new one.
		 */
		if (last[fd] != SLT_SessionClose)
#ifdef __ORIGIN
			VSB_printf(ob[fd], "%5d %-12s %c %s\n", fd, "Interrupted", type, VSL_tags[tag]);
#else
			VSB_printf(ob[fd], "%d ~ %.*s\n", tag, len, ptr);
#endif
		printf("%s\n", VSL_tags[tag]);
		h_order_finish(fd, vd);
	}

	last[fd] = tag;

	switch (tag) {
	case SLT_VCL_call:
		if (flg[fd] & F_INVCL)
			VSB_cat(ob[fd], "\n");
		else
			flg[fd] |= F_INVCL;
#ifdef __ORIGIN
		VSB_printf(ob[fd], "%5d %-12s %c %.*s", fd, VSL_tags[tag], type, len, ptr);
#else
		VSB_printf(ob[fd], "%d ~ %.*s", tag, len, ptr);
#endif
		return (0);
	case SLT_VCL_trace:
	case SLT_VCL_return:
		if (flg[fd] & F_INVCL) {
			VSB_cat(ob[fd], " ");
			VSB_bcat(ob[fd], ptr, len);
			return (0);
		}
		break;
	default:
		break;
	}
	if (flg[fd] & F_INVCL) {
		VSB_cat(ob[fd], "\n");
		flg[fd] &= ~F_INVCL;
	}

#ifdef __ORIGIN
	VSB_printf(ob[fd], "%5d %-12s %c %.*s\n", fd, VSL_tags[tag], type, len, ptr);
#else
	VSB_printf(ob[fd], "%d ~ %.*s\n", tag, len, ptr);
#endif
	
	switch (tag) {
	case SLT_ReqEnd:
	case SLT_BackendClose:
	case SLT_BackendReuse:
	case SLT_StatSess:
		h_order_finish(fd, vd);
		break;
	default:
		break;
	}
	return (0);
}

static void
do_order(struct VSM_data *vd)
{
	int i;

	if (!b_flag) {
		VSL_Select(vd, SLT_SessionOpen);
		VSL_Select(vd, SLT_SessionClose);
		VSL_Select(vd, SLT_ReqEnd);
	}
	if (!c_flag) {
		VSL_Select(vd, SLT_BackendOpen);
		VSL_Select(vd, SLT_BackendClose);
		VSL_Select(vd, SLT_BackendReuse);
	}
	while (1) {
		i = VSL_Dispatch(vd, h_order, vd);
		if (i == 0) {
			clean_order(vd);
			AZ(fflush(stdout));
		}
		else if (i < 0)
			break;
	}
	clean_order(vd);
}

/*--------------------------------------------------------------------*/

static volatile sig_atomic_t reopen;

static void
sighup(int sig)
{

	(void)sig;
	reopen = 1;
}

static int
open_log(const char *w_arg, int a_flag)
{
	int fd, flags;

	flags = (a_flag ? O_APPEND : O_TRUNC) | O_WRONLY | O_CREAT;
#ifdef O_LARGEFILE
	flags |= O_LARGEFILE;
#endif
	if (!strcmp(w_arg, "-"))
		fd = STDOUT_FILENO;
	else
		fd = open(w_arg, flags, 0644);
	if (fd < 0) {
		perror(w_arg);
		exit(1);
	}
	return (fd);
}

static void
do_write(const struct VSM_data *vd, const char *w_arg, int a_flag)
{
	int fd, i, l;
	uint32_t *p;

	fd = open_log(w_arg, a_flag);
	XXXAN(fd >= 0);
	(void)signal(SIGHUP, sighup);
	while (1) {
		i = VSL_NextLog(vd, &p, NULL);
		if (i < 0)
			break;
		if (i > 0) {
			l = VSL_LEN(p);
			i = write(fd, p, 8L + VSL_WORDS(l) * 4L);
			if (i < 0) {
				perror(w_arg);
				exit(1);
			}
		}
		if (reopen) {
			AZ(close(fd));
			fd = open_log(w_arg, a_flag);
			XXXAN(fd >= 0);
			reopen = 0;
		}
	}
	exit(0);
}

static void
usage(void)
{
	fprintf(stderr, "usage: varnishlog "
	    "%s [-aDV] [-o [tag regex]] [-n varnish_name] [-P file] [-w file]\n", VSL_USAGE);
	exit(1);
}

int
main(int argc, char * const *argv)
{
	int c;
	int a_flag = 0, D_flag = 0, O_flag = 0, u_flag = 0, m_flag = 0;
	const char *P_arg = NULL;
	const char *w_arg = NULL;
	struct vpf_fh *pfh = NULL;
	struct VSM_data *vd;

	vd = VSM_New();
	VSL_Setup(vd);

	while ((c = getopt(argc, argv, VSL_ARGS "aDP:uVw:oO")) != -1) {
		switch (c) {
		case 'a':
			a_flag = 1;
			break;
		case 'b':
			b_flag = 1;
			AN(VSL_Arg(vd, c, optarg));
			break;
		case 'c':
			c_flag = 1;
			AN(VSL_Arg(vd, c, optarg));
			break;
		case 'D':
			D_flag = 1;
			break;
		case 'o': /* ignored for compatibility with older versions */
			break;
		case 'O':
			O_flag = 1;
			break;
		case 'P':
			P_arg = optarg;
			break;
		case 's':	
			s_flag = 1;			
			break;		
		case 'u':
			u_flag = 1;
			break;
		case 'V':
			VCS_Message("varnishlog");
			exit(0);
		case 'w':
			w_arg = optarg;
			break;
		case 'm':
			m_flag = 1;
			/* FALLTHROUGH */
		default:
			if (VSL_Arg(vd, c, optarg) > 0)
				break;
			usage();
		}
	}

	if (O_flag && m_flag)
		usage();

	if ((argc - optind) > 0)
		usage();

	if (VSL_Open(vd, 1))
		exit(1);

	if (P_arg && (pfh = VPF_Open(P_arg, 0644, NULL)) == NULL) {
		perror(P_arg);
		exit(1);
	}

	if (D_flag && varnish_daemon(0, 0) == -1) {
		perror("daemon()");
		if (pfh != NULL)
			VPF_Remove(pfh);
		exit(1);
	}

	if (pfh != NULL)
		VPF_Write(pfh);

	if (w_arg != NULL)
		do_write(vd, w_arg, a_flag);

	if (u_flag)
		setbuf(stdout, NULL);

  if(s_flag){
  	if (openfifo(FIFO_FILE) == -1) {
  		perror("Cannot open fifo");
  		exit(1);
  	}
 	}

	if (!O_flag)
		do_order(vd);

	while (VSL_Dispatch(vd, VSL_H_Print, stdout) >= 0) {
		if (fflush(stdout) != 0) {
			perror("stdout");
			break;
		}
	}

	if (pfh != NULL)
		VPF_Remove(pfh);

	if (fifo > 0)
		close(fifo);

	exit(0);
}
