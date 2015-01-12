
/*
 On linux, build with:
 
  sudo apxs -i -I/usr/include/postgresql -c mod_pg.c -lpq

 */


#include <stdio.h>

#include "apr_strings.h"
#include "ap_config.h"
#include "httpd.h"
#include "http_config.h"
#include "http_protocol.h"
#include "http_log.h"
#include "util_script.h"
#include "http_main.h"
#include "http_request.h"

#include "util_cookies.h"

#include "mod_core.h"
#include "http_core.h"

#include <stdio.h>
#include <string.h>
#include <libpq-fe.h>

extern module pg_module;

struct pq_dir_config {
    PGconn *conn;
//    const char *repo_path;
    const char *connection_string;
    const char *active_conn_string;
    const char *stored_proc;
    const char *command;
    const char *path;
    apr_table_t *parm_headers;
    apr_table_t *parm_cookies;
    int location;
    apr_hash_t *connection_hash;
};

static void pq_child_init(apr_pool_t *pool, server_rec *s) {
}

typedef struct {
    char *buf;
    int len;
} buf_and_len;

apr_table_do_callback_fn_t paramcb;
int paramcb(void *rec, const char *k, const char *v) {
    buf_and_len *cc = (buf_and_len *)rec;
    char *caten = cc->buf;
    int len = cc->len;
    if ( 0 == strcmp(k, "db-connexion") ) return 1;
    strncat(caten, "\"", len);
    strncat(caten, k, len);
    strncat(caten, "\": \"", len);
    strncat(caten, v, len);
    strncat(caten, "\",", len);
    return 1;
}

const size_t MAX_POST_SIZE=1024000;

typedef struct {
    apr_table_t *from;
    apr_table_t *to;
} xtbls;

apr_table_do_callback_fn_t setfrom;
int setfrom(void *rec, const char *k, const char *v) {
    xtbls *xt = (xtbls *)rec;
    apr_table_add(xt->to, v, apr_table_get(xt->from, k));
    return 1;
}

typedef struct {
    apr_table_t *to;
    request_rec *r;
} ytbls;


apr_table_do_callback_fn_t setfromcookie;
int setfromcookie(void *rec, const char *k, const char *v) {
    ytbls *yt = (ytbls *)rec;
    const char *c;
    ap_cookie_read(yt->r, k, &c, 0);
    apr_table_add(yt->to, v, c);
    return 1;
}


apr_table_do_callback_fn_t bparm;
int bparm(void *rec, const char *k, const char *v) {
    buf_and_len *cc = (buf_and_len *)rec;
    char *caten = cc->buf;
    int len = cc->len;
    if (v != NULL) {
      strncat(caten, "\"", len);
      strncat(caten, k, len);
      strncat(caten, "\": \"", len);
      strncat(caten, v, len);
      strncat(caten, "\",", len);
    }
    return 1;
}

char *table_to_json(apr_pool_t *p, apr_table_t *t) {
    buf_and_len bl;
    char buf[16384];
    bl.buf = &buf[0];
    bl.len = 16380;
    buf[16380]='\0';
    buf[0]='{';
    buf[1]='\0';
    apr_table_do(bparm, &bl, t, NULL);
    buf[strlen(buf)-1]='\0';
    strncat(buf,"}",bl.len+1);
    return apr_pstrdup(p, buf);
}

static int pq_handler(request_rec *r) {
    apr_status_t rv;

    if (strcmp(r->handler, "postgresql")) {
        return DECLINED;
    }
    
    r->allowed |= (AP_METHOD_BIT << M_POST);
    r->allowed |= (AP_METHOD_BIT << M_GET);
    
    int isapost = 0, isaget = 0;
    if (r->method_number == M_POST) { isapost = 1; }
    else if (r->method_number == M_GET) { isaget = 1; }
    else return DECLINED;

    struct pq_dir_config *gdc = (struct pq_dir_config *) ap_get_module_config(r->per_dir_config, &pg_module);
    
/*
    core_dir_config *cd = ap_get_core_module_config(r->per_dir_config);
    core_request_config *core = ap_get_core_module_config(r->request_config);

    
    const char *pgconn = NULL;
    const char *connstr = gdc->connection_string;
    */
    
    /* Get the sessionid from the cookie, or create a new sessionid and set the cookie */
    // ap_cookie_read(r, "postgresql", &pgconn, 0);

/*
    ap_cookie_read(r, "JSESSIONID", &pgconn, 0);
    const size_t SESSION_SIZE=32;
    unsigned char sbuf[SESSION_SIZE];
    char xbuf[1+SESSION_SIZE * 2];
 */

//    if (pgconn == NULL) { // there is no cookie
//        return HTTP_NETWORK_AUTHENTICATION_REQUIRED; // somebody needs to have set JSESSIONID
        // but it is not I
/*        apr_generate_random_bytes(sbuf, SESSION_SIZE);
        ap_bin2hex(sbuf, SESSION_SIZE, &xbuf[0]);
        ap_cookie_write(r, "postgresql", xbuf, "path=/", ONE_YEAR, r->headers_out, NULL);
        pgconn = &xbuf[0];
 */
//    }
    
    const char *docroot = gdc->path == NULL || gdc->location ? ap_context_document_root(r) : gdc->path;
    const char *pi;
    if (gdc->location) {
        pi = r->uri + strlen(gdc->path); }
    else {
        pi = r->filename + strlen(docroot);
    }
    while(*pi == '/') pi++;
    
    char post[MAX_POST_SIZE];
    size_t postlen = 0;
    
    conn_rec *c = r->connection;
    
    if (isaget) goto doget;
    
    /* Get the post data here */
    
    apr_bucket_brigade *ibb = apr_brigade_create(r->pool, c->bucket_alloc);
    apr_bucket *e;
    rv = ap_get_brigade(r->input_filters, ibb, AP_MODE_READBYTES, APR_BLOCK_READ, HUGE_STRING_LEN);
    if (rv != APR_SUCCESS) {
        if (APR_STATUS_IS_TIMEUP(rv)) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01224) "Timeout during reading request entity data");
            return HTTP_REQUEST_TIME_OUT;
        }
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01225) "Error reading request entityt data");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    const char *buf;
    size_t len;
    for (e = APR_BRIGADE_FIRST(ibb);
         e != APR_BRIGADE_SENTINEL(ibb);
         e = APR_BUCKET_NEXT(e)) {
            if (APR_BUCKET_IS_EOS(e)) break;
            rv = apr_bucket_read(e, &buf, &len, APR_BLOCK_READ);
            if (rv != APR_SUCCESS || len == 0) break;
        
        if (postlen + len < MAX_POST_SIZE) {
            memcpy(post+postlen, buf, len);
            postlen += len;
        } else {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01255) "Post exceeds maximum size");
            return HTTP_INTERNAL_SERVER_ERROR;
        }
            
    }
    apr_brigade_cleanup(ibb);
    post[postlen]='\0';

    
    goto gotpost;
    
doget:;
    const char *ppi = r->path_info;
    const char *empty = "";
    if (ppi == NULL) { postlen = 0; ppi = empty; }
    else {
        if (*ppi == '/') { ppi += 1; }
        postlen = strlen(ppi);
        if (postlen > MAX_POST_SIZE-1) postlen = MAX_POST_SIZE-1;
    }
    /* use a "path_info" operation (which could default to "eval" */
    postlen = snprintf(post, MAX_POST_SIZE, "{\"op\":\"get\",\"path\":\"%s\"", ppi);
    if (postlen > MAX_POST_SIZE) {
        postlen = 0;
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(01443) "Path info exceeds maximum size");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    apr_table_t *reqparams;
    ap_args_to_table(r, &reqparams);
    strncat(post, ", \"args\":{ ", MAX_POST_SIZE);
    buf_and_len bl;
    bl.buf = post;
    bl.len = MAX_POST_SIZE;
    apr_table_do(paramcb, &bl, reqparams, NULL);
    post[strlen(post)-1] = '\0';  // shorten by removing the trailing , (if any)
    strncat(post, "}}", MAX_POST_SIZE);
    
gotpost:;
    
    
    /* the connection logic is as follows:
           The request is either pre-login or post-login
               Pre-Login takes the ip-address, session-id, NULL, and database request
                            executes them under a generic (not-logged-in) account, and returns the result
               Post-Login takes the ip-address, session-id, desired-user, and database request
                            validates the session (check_session? validate_session), 
                            runs the "become" code, and returns the result.
     */
    
    
    /* connect to the server (using generic-account?) */
    
    
    const char *df = gdc->connection_string;
    const char *tcd;
    ap_cookie_read(r, "db_conn_string", &tcd, 0);

    const char *tcs = tcd;
    
    // // for catching internal redirects
    // const char *dn = apr_table_get(r->headers_in, "db_conn_string");
    // if (dn != NULL) tcs = dn;
    
    if (tcd == NULL) tcs = df; // put the default back
    else tcs = apr_pstrcat(r->pool, df, " ", tcd, NULL );
    
    if (tcd != NULL) apr_table_add(r->headers_out,"X-Db", tcd);

    // *********************** r0ml


    if (gdc->conn == NULL || strcmp(gdc->active_conn_string, tcs)) {
        if (gdc->conn != NULL) { PQfinish(gdc->conn); gdc->conn = NULL; }
        if (gdc->active_conn_string != NULL) free(gdc->active_conn_string);
        gdc->active_conn_string = strdup(tcs);
        fprintf(stderr, "db connect to %s\n", tcs);
        gdc->conn = PQconnectdb(tcs);
        if (gdc->conn == NULL || CONNECTION_OK != PQstatus(gdc->conn)) {
            const char *errm = gdc->conn == NULL ? "unknown failure" : PQerrorMessage(gdc->conn);
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(09050) "PQconnectdb failed: %s", errm);
            if (gdc->conn != NULL) {
                PQfinish(gdc->conn);
                gdc->conn = NULL;
            }
            return HTTP_INTERNAL_SERVER_ERROR;
        }
    }
    
    // const char *uagent = apr_table_get(r->headers_in, "User-Agent");
    const char *paramValues[2];
    
    xtbls xx;
    xx.from = r->headers_in;
    xx.to = apr_table_make(r->pool, 10);
    
    apr_table_set(xx.to, "ip_address", r->useragent_ip);
    
    apr_table_do(setfrom, &xx, gdc->parm_headers, NULL);

    ytbls yy;
    yy.to = xx.to;
    yy.r = r;
    apr_table_do(setfromcookie, &yy, gdc->parm_cookies, NULL);

    char *jt = table_to_json(r->pool, yy.to);
    

    paramValues[0]=jt;  // this is the user-agent string
    paramValues[1] = postlen == 0 ? NULL : post;
    
    int toReturn = OK;
    
    PGresult *sres = PQexecParams(gdc->conn, gdc->command, 2, NULL, paramValues, NULL, NULL, 0);
    if (PQresultStatus(sres) != PGRES_TUPLES_OK) {
        const char *dberr = PQresultErrorMessage(sres);
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(09061) "postgresql query error: %s", dberr );
        PQfinish(gdc->conn);
        gdc->conn = NULL;
        apr_table_add(r->err_headers_out, "X-DbErr", dberr);
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    int ns = PQntuples(sres);
    if (ns != 1) {
        const char *dberr = "expected single row from api.api";
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(93039) "%s", dberr);
        apr_table_add(r->err_headers_out, "X-DbErr", dberr);
        return  HTTP_INTERNAL_SERVER_ERROR;
    }

    apr_bucket_brigade *bb = apr_brigade_create(r->pool, c->bucket_alloc);
    const char *xres = PQgetvalue(sres,0,0);
    apr_brigade_write(bb, NULL, NULL, xres, strlen(xres));
    PQclear(sres);
    ap_set_content_type(r, "application/json");
    
    apr_bucket *b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01236) "mod_pg: ap_pass_brigade failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    return OK; // OK is ambiguous -- should be 0
}


static void register_hooks(apr_pool_t *p) {
    ap_hook_handler(pq_handler,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_child_init(pq_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *init_pq_cookie(cmd_parms *cmd, void *dconf, const char *pn, const char *val) {
    struct pq_dir_config *gdc = (struct pq_dir_config *)dconf;
    apr_table_add(gdc->parm_cookies, pn, val == NULL ? pn : val);
    return NULL;
}

static const char *init_pq_header(cmd_parms *cmd, void *dconf, const char *pn, const char *val) {
    struct pq_dir_config *gdc = (struct pq_dir_config *)dconf;
    apr_table_add(gdc->parm_headers, pn, val == NULL ? pn : val);
    return NULL;
}

static const char *init_pq_config(cmd_parms *cmd, void *dconf, const char *pn, const char *dv) {
    struct pq_dir_config *gdc = (struct pq_dir_config *)dconf;
    
    gdc->parm_headers = apr_table_make(cmd->pool, 10);
    gdc->parm_cookies = apr_table_make(cmd->pool, 10);
    
    gdc->connection_string = apr_pstrcat(cmd->pool, dv," ",NULL);
    gdc->active_conn_string = NULL;
    gdc->conn = NULL;
    
    char cmdbuf[256];
    snprintf(cmdbuf, 255, "select * from %s($1, $2)", pn);
    gdc->stored_proc = apr_pstrdup(cmd->pool, pn);
    gdc->command = apr_pstrdup(cmd->pool, cmdbuf);

    gdc->path = cmd->path == NULL || 0 == strlen(cmd->path) ? NULL : apr_pstrdup(cmd->pool, cmd->path);
    gdc->location = 0;
    if (NULL == cmd->directive->parent) {
        // this means server level config
        return NULL;
    }
    const char *parent = cmd->directive->parent->directive;
    if (0 == strcasecmp("<Location", parent)) {
        gdc->location = 1;
    }
    if (0 == strcasecmp("<LocationMath", parent)) {
        gdc->location = 1; // return "Git in LocationMatch stanza not supported";
    }
    
    if (0 == strcasecmp("<Directory", parent)) {
        return "PotgreSQL configuration should be in a Location, not a Directory";
    }
    return NULL;
}

static void *create_pq_dir_config(apr_pool_t *pool, char *d) {
    struct pq_dir_config *n = (struct pq_dir_config *)apr_pcalloc(pool, sizeof(struct pq_dir_config));
    n->connection_string = "";
    /* The hash table must be created during configuration */
    n->connection_hash = apr_hash_make(pool);
    return n;
}

static const command_rec pq_cmds[] = {
    AP_INIT_TAKE2("PostgreSQL", init_pq_config, NULL, RSRC_CONF|ACCESS_CONF, "PostgreSQL stored-procedure and connection-string"),
    AP_INIT_TAKE12("PostgresCookie", init_pq_cookie, NULL, RSRC_CONF|ACCESS_CONF, "Cookie to pass to the database api procedure"),
    AP_INIT_TAKE12("PostgresHeader", init_pq_header, NULL, RSRC_CONF|ACCESS_CONF, "Request header to pass to the database api procedure"),
    {NULL}
};

AP_DECLARE_MODULE(pg) = {
    STANDARD20_MODULE_STUFF,
    create_pq_dir_config,              /* create per-directory (location, really) config structure */
    NULL,              /* merge per-directory config structures */
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    pq_cmds,              /* command apr_table_t */
    register_hooks     /* register hooks */
};

