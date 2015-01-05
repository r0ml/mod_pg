
/*
 On linux, build with:
 
  sudo apxs -i -c mod_pg.c -lpq

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

const int ONE_YEAR = 31536000;

/* HOME must be set to a directory that the httpd daemon has access to -- otherwise 
   the attempt to open the git repository will fail */

extern module pg_module;

struct pq_dir_config {
    PGconn *conn;
//    const char *repo_path;
    const char *connection_string;
    const char *stored_proc;
    const char *command;
    const char *path;
    int location;
    apr_hash_t *connection_hash;
};

static void pq_child_init(apr_pool_t *pool, server_rec *s) {
}

const size_t MAX_POST_SIZE=1024000;

apr_table_do_callback_fn_t paramcb;
int paramcb(void *rec, const char *k, const char *v) {
    char *caten = (char *)rec;
    strncat(caten, "\"", MAX_POST_SIZE);
    strncat(caten, k, MAX_POST_SIZE);
    strncat(caten, "\": \"", MAX_POST_SIZE);
    strncat(caten, v, MAX_POST_SIZE);
    strncat(caten, "\",", MAX_POST_SIZE);
    return 1;
}

static int pq_handler(request_rec *r) {
    apr_status_t rv;

    if (strcmp(r->handler, "postgresql")) {
        return DECLINED;
    }
    
    /* Must be a POST */
    r->allowed |= (AP_METHOD_BIT << M_POST);
    r->allowed |= (AP_METHOD_BIT << M_GET);
    
    int isapost = 0, isaget = 0;
    if (r->method_number == M_POST) { isapost = 1; }
    else if (r->method_number == M_GET) { isaget = 1; }
    else return DECLINED;

    struct pq_dir_config *gdc = (struct pq_dir_config *) ap_get_module_config(r->per_dir_config, &pg_module);
    
    core_dir_config *cd = ap_get_core_module_config(r->per_dir_config);
    core_request_config *core = ap_get_core_module_config(r->request_config);

    
    const char *pgconn = NULL;
    const char *connstr = gdc->connection_string;
    
    /* Get the sessionid from the cookie, or create a new sessionid and set the cookie */
    // ap_cookie_read(r, "postgresql", &pgconn, 0);

    ap_cookie_read(r, "JSESSIONID", &pgconn, 0);
    const size_t SESSION_SIZE=32;
    unsigned char sbuf[SESSION_SIZE];
    char xbuf[1+SESSION_SIZE * 2];

    if (pgconn == NULL) { // there is no cookie
        return HTTP_NETWORK_AUTHENTICATION_REQUIRED; // somebody needs to have set JSESSIONID
        // but it is not I
/*        apr_generate_random_bytes(sbuf, SESSION_SIZE);
        ap_bin2hex(sbuf, SESSION_SIZE, &xbuf[0]);
        ap_cookie_write(r, "postgresql", xbuf, "path=/", ONE_YEAR, r->headers_out, NULL);
        pgconn = &xbuf[0];
 */
    }
    
    const char *docroot = gdc->path == NULL || gdc->location ? ap_context_document_root(r) : gdc->path;
    const char *rp = docroot; // gdc->repo_path
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
    apr_table_do(paramcb, post, reqparams, NULL);
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
    if (gdc->conn == NULL) {
        gdc->conn = PQconnectdb(gdc->connection_string);
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
    
    const char *uagent = apr_table_get(r->headers_in, "User-Agent");
    const char *paramValues[5];
    paramValues[0]=r->useragent_ip;  // this is the requestor ip address
    paramValues[1]=uagent;  // this is the user-agent string
    paramValues[2]=pgconn;  // this is the session id
    paramValues[3]=""; // this should be the session user -- but dont know how to do that
    if (postlen == 0) paramValues[4] = NULL; else paramValues[4]=post;
    
    PGresult *sres = PQexecParams(gdc->conn, gdc->command, 5, NULL, paramValues, NULL, NULL, 0);
    if (PQresultStatus(sres) != PGRES_TUPLES_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(09061) "postgresql query error: %s", PQresultErrorMessage(sres) );
        PQfinish(gdc->conn);
        gdc->conn = NULL;
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    int ns = PQntuples(sres);
    if (ns != 1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(93039)
                      "expected single row from api.api");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
/*
    PQgetvalue(sres,0,0); // email for the session (logged in as)
    PQgetvalue(sres,0,1); // company
    PQgetvalue(sres,0,2); // role
    PQgetvalue(sres,0,3); // vursion
    PQgetvalue(sres,0,4); // intercom

    const char *paramValues[3];
    paramValues[0]="1.2.3.4"; // the IP address
    paramValues[1]="user-agent"; // the User agent
    paramValues[2]=post;
    PGresult *res = PQexecParams(gdc->conn, "select api.login($1,$2,$3)", 3, NULL, paramValues, NULL, NULL, 0);
    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(09061) "postgresql query error: %s", PQresultErrorMessage(res) );
        PQfinish(gdc->conn);
        gdc->conn = NULL;
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    int n = PQntuples(res);
    if (n != 1) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, APLOGNO(93039)
                      "not one row returned");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
     */

    
    const char *xres = PQgetvalue(sres,0,0);

//    const char *xres = "this is a test";

    apr_bucket_brigade *bb = apr_brigade_create(r->pool, c->bucket_alloc);
    apr_brigade_write(bb, NULL, NULL, xres, strlen(xres));
    PQclear(sres);

    apr_bucket *b = apr_bucket_eos_create(c->bucket_alloc);
    APR_BRIGADE_INSERT_TAIL(bb, b);
    rv = ap_pass_brigade(r->output_filters, bb);
    if (rv != APR_SUCCESS) {
        ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r, APLOGNO(01236)
                      "mod_pg: ap_pass_brigade failed");
        return HTTP_INTERNAL_SERVER_ERROR;
    }
    
    ap_set_content_type(r, "application/json");
    
    return OK; // OK is ambiguous -- should be 0
}


static void register_hooks(apr_pool_t *p) {
    ap_hook_handler(pq_handler,NULL,NULL,APR_HOOK_MIDDLE);
    ap_hook_child_init(pq_child_init, NULL, NULL, APR_HOOK_MIDDLE);
}

static const char *init_pq_config(cmd_parms *cmd, void *dconf, const char *pn, const char *dv) {
    struct pq_dir_config *gdc = (struct pq_dir_config *)dconf;
//    gdc->repo_path = apr_pstrdup(cmd->pool ,rep);
    gdc->connection_string = apr_pstrdup(cmd->pool, dv);

    char cmdbuf[256];
    snprintf(cmdbuf, 255, "select * from %s($1, $2, $3, $4, $5)", pn);
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
    
/*
    if (0 == strcasecmp("<Directory", parent)) {
        return "Git configuration should be in a Location, not a Directory";
    }
 */
    return NULL;
}

static void *create_pq_dir_config(apr_pool_t *pool, char *d) {
    struct pq_dir_config *n = (struct pq_dir_config *)apr_pcalloc(pool, sizeof(struct pq_dir_config));
    n->connection_string = "";
    /* The hash table must be created during configuration */
    n->connection_hash = apr_hash_make(pool);
    return n;
}

/*
 static void *merge_git_dir_config(apr_pool_t* pool, void *base, void *add) {
    struct git_dir_config *n = create_git_dir_config(pool, NULL);
    struct git_dir_config *na = add;
    n->repo = na -> repo;
    n->repo_path = na->repo_path == NULL ? NULL : apr_pstrdup(pool, na->repo_path);
    n->default_vursion = na->repo_path == NULL ? NULL : apr_pstrdup(pool, na->default_vursion);
    return add;
}
*/

static const command_rec pq_cmds[] = {
    AP_INIT_TAKE2("PostgreSQL", init_pq_config, NULL, RSRC_CONF|ACCESS_CONF, "PostgreSQL connection string"),
    {NULL}
};

AP_DECLARE_MODULE(pg) = {
    STANDARD20_MODULE_STUFF,
    create_pq_dir_config,              /* create per-directory (location, really) config structure */
//    merge_git_dir_config,              /* merge per-directory config structures */
    NULL,
    NULL,              /* create per-server config structure */
    NULL,              /* merge per-server config structures */
    pq_cmds,              /* command apr_table_t */
    register_hooks     /* register hooks */
};

