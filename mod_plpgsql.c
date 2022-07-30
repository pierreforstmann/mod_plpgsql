/*
 * Copyright (C) 2022 Pierre Forstmann.
 *
 *
 * plpgsql.c
 *
 */
#include "apr_buckets.h"
#include "util_filter.h"

#include "ap_config.h"
#include "ap_provider.h"
#include "apr_strings.h"
#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_connection.h"
#include "http_protocol.h"
#include "http_request.h"
#include "ap_mmn.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(plpgsql);
#endif

#include "libpq-fe.h"
#define CONNECT_STRING_MAX_LENGTH	100

module AP_MODULE_DECLARE_DATA plpgsql;

typedef struct {
    int enable;
    char *username;
    char *password;
    char *hostname;
    char *port;
    char *dbname;
} plpgsqlConfig;

/*
 * Main apache functions
 */

void *create_plpgsql_dir_config(apr_pool_t *p, char *path)
{
    plpgsqlConfig *config = apr_pcalloc(p, sizeof(plpgsqlConfig));
    config->enable = 1;
    config->username = NULL;
    config->password = NULL;
    config->hostname = NULL;
    config->port = 0;
    config->dbname = NULL;

    return (void *)config;
}

static const char *plpgsql_username(cmd_parms *cmd, void *mconfig, const char *arg)
{
    plpgsqlConfig *config = (plpgsqlConfig *)mconfig;
    config->username = (char *)apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *plpgsql_password(cmd_parms *cmd, void *mconfig, const char *arg)
{
    plpgsqlConfig *config = (plpgsqlConfig *)mconfig;
    config->password = (char *)apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *plpgsql_hostname(cmd_parms *cmd, void *mconfig, const char *arg)
{
    plpgsqlConfig *config = (plpgsqlConfig *)mconfig;
    config->hostname = (char *)apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *plpgsql_port(cmd_parms *cmd, void *mconfig, const char *arg)
{
    plpgsqlConfig *config = (plpgsqlConfig *)mconfig;
    config->port = (char *)apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static const char *plpgsql_dbname(cmd_parms *cmd, void *mconfig, const char *arg)
{
    plpgsqlConfig *config = (plpgsqlConfig *)mconfig;
    config->dbname = (char *)apr_pstrdup(cmd->pool, arg);
    return NULL;
}

static int plpgsql_handler(request_rec *r)
{
    apr_table_t *args = NULL;

    char conninfo[CONNECT_STRING_MAX_LENGTH];
    PGconn 	*conn;
    PGresult	*res;

    	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                "plpgsql_handler: entry");

    plpgsqlConfig *config = (plpgsqlConfig *)
        ap_get_module_config(r->per_dir_config, &plpgsql_module);

    if (strcmp(r->handler, "plpgsql-handler")) {
        return DECLINED;
    }

    if(config != NULL) {
        if (!config->enable) {
           return DECLINED;
        }
    } else {
        return DECLINED;
    }

    /*
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                "base_dir: %s", config->base_dir);
		*/

    if (r->header_only) {
        return OK;
    }

    conninfo[0] = '\0';
    strcat(conninfo, "host=");
    strcat(conninfo, config->hostname);
    strcat(conninfo, " ");
    strcat(conninfo, "port=");
    strcat(conninfo, config->port);
    strcat(conninfo, " ");
    strcat(conninfo, "dbname=");
    strcat(conninfo, config->dbname);
    strcat(conninfo, " ");
    strcat(conninfo, "user=");
    strcat(conninfo, config->dbname);
    strcat(conninfo, " ");
    strcat(conninfo, "password=");
    strcat(conninfo, config->password);
    conn = PQconnectdb(conninfo);
    if (PQstatus(conn) == CONNECTION_BAD)
    {
    	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                "%s", PQerrorMessage(conn));
        ap_rputs("ERROR: cannot connect \n", r);
	return OK;
    }
    ap_rputs("Connected to PG ... \n", r);

    /*
     *
     *

    if(util_parse_get(r, &args) == OK) {
    } else if(util_parse_post(r, &args) == OK) {
    } else {
        return DECLINED;
    }

    ap_set_content_type(r, "text");

    apr_table_set(r->err_headers_out, PROTOCOL_HEADER,
        PROTOCOL_VERSION);

    if(config->db_file != NULL) {
        db_name = config->db_file;
    } else {
        db_name = (char *)apr_table_get(args, DB_FILE_PARAM);
        if(! db_name) {
            apr_table_set(r->err_headers_out, ERROR_HEADER,
                    "No Database name specified");
            ap_rputs("ERROR: no database name specified\n", r);
            return OK;
        }

        ap_getparents(db_name);
    }

    if(config->base_dir != NULL) {
        char *new_db_name = (char *)apr_pstrcat(
                r->pool, config->base_dir, "/", db_name, NULL);
        ap_no2slash(new_db_name);
        db_name = new_db_name;
    }


    if(stat(db_name, &db_stat) != 0) {
    	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                "db_name: %s not found errno=%d", db_name, errno);
        ap_rputs("ERROR: database not found\n", r);
        return OK;
    }

    if(config->query != NULL) {
        query = config->query;
    } else {
        query = (char *)apr_table_get(args, SQL_STATEMENT_PARAM);
    }

    if(! query) {
        apr_table_set(r->err_headers_out, ERROR_HEADER,
                "No query specified");
        ap_rputs("ERROR: no query specified\n", r);
        return OK;
    }

    sqlite_cb_s.r = r;
    sqlite_cb_s.flag = 0;  

    rc = sqlite3_open(db_name, &db);
    if(rc != SQLITE_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                "Error opening db %s: %s", db_name, sqlite3_errmsg(db));
        apr_table_mergen(r->headers_out, ERROR_HEADER, sqlite3_errmsg(db));
        ap_rputs("ERROR: error opening database\n", r);
	return OK;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server,
                "Connected to database: %s", db_name);

    if (rc != SQLITE_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                "Error executing query: %s", "SELECT SQLITE VERSION()");
        ap_rputs("ERROR: error preparing SELECT SQLITE_VERSION \n", r);
        return OK;
    }    

    rc = sqlite3_step(res);
    if (rc == SQLITE_ROW) {
    	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "Connected to SQLite version: %s",
                     sqlite3_column_text(res, 0));
    } else {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                "Failed to get SQLite version: %s", sqlite3_errmsg(db));
        ap_rputs("ERROR: error executing SELECT SQLITE_VERSION \n", r);
        return OK;
    }


    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "query=<%s>",
            query);

    if((err =
            sqlite3_exec(db, query, sqlite_cb , &sqlite_cb_s, &errmsg))
            != SQLITE_OK) {
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                "Error executing query: %s", sqlite3_errstr(err));
        ap_log_error(APLOG_MARK, APLOG_ERR, 0, r->server,
                "Error executing query: %s", errmsg);
        apr_table_set(r->err_headers_out, ERROR_HEADER, errmsg);
        ap_rprintf(r, "ERROR: error executing query: %s \n", errmsg);
        sqlite3_free(errmsg);
        return OK;
    }
    *
    *
    */

    
    return OK;

}

static void register_hooks(apr_pool_t *p)
{
  ap_hook_handler(plpgsql_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

static const command_rec plpgsql_cmds[] = 
{
    AP_INIT_TAKE1("PGUsername", plpgsql_username, NULL, ACCESS_CONF,
                 "PostgreSQL user name"),
    AP_INIT_TAKE1("PGPassword", plpgsql_password, NULL, ACCESS_CONF,
                 "PostgreSQL password"),
    AP_INIT_TAKE1("PGHostname", plpgsql_hostname, NULL, ACCESS_CONF,
                 "PostgresSQL instance host name"),
    AP_INIT_TAKE1("PGPort", plpgsql_port, NULL, ACCESS_CONF,
                 "PostgresSQL instance port number"),
    AP_INIT_TAKE1("PGDatabase", plpgsql_dbname, NULL, ACCESS_CONF,
                 "PostgresSQL database name"),
    { NULL }
};

module AP_MODULE_DECLARE_DATA plpgsql_module = {
    STANDARD20_MODULE_STUFF,
    create_plpgsql_dir_config,		/* create per-directory config structure */
    NULL,		                /* merge per-directory config structures */
    NULL,	                        /* create per-server config structure */
    NULL,			        /* merge per-server config structures */
    plpgsql_cmds,			/* command apr_table_t */
    register_hooks		        /* register hooks */
};
