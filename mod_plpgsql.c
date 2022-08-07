/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Copyright (C) 2022 Pierre Forstmann.
 *
 * mod_plpgsql.c
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
#include "apr_tables.h"
#include "util_script.h"
#include "apr_uri.h"

#ifdef APLOG_USE_MODULE
APLOG_USE_MODULE(plpgsql);
#endif

#include "libpq-fe.h"

module AP_MODULE_DECLARE_DATA plpgsql;

typedef struct {
    int enable;
    char *username;
    char *password;
    char *hostname;
    char *port;
    char *dbname;
} plpgsqlConfig;

static	char *pg_call_statement;
static	int  argc = 0;

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

static int plpgsql_cbf(void *rec, const char *key, const char *value)
{
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, ((request_rec *)rec)->server, "plpgsql_handler: plpgsql_cbf: key=%s value=%s", key, value);
    if (argc == 0)
	    pg_call_statement = apr_psprintf(((request_rec *)rec)->pool, "%s'%s'", pg_call_statement, value);
    else
	    pg_call_statement = apr_psprintf(((request_rec *)rec)->pool, "%s,'%s'", pg_call_statement, value);
    argc++;
    return 1;
}

static int plpgsql_handler(request_rec *r)
{
    apr_table_t *args = NULL;
    apr_uri_t 	uri;
    apr_status_t status;

    char 	*conninfo;
    PGconn 	*conn;
    PGresult	*res;
    ExecStatusType pgstatus;
    char	*proc;
    char	*endofprocname;
    char	*stmt = NULL;
    char	*cmdstatus;
    char	*value;
    int		i;

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: entry");
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: filename=%s",r->filename );
    status = apr_uri_parse(r->pool, r->uri, &uri);
    if (status != APR_SUCCESS) {
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: apr_uri_parse error");
        return HTTP_INTERNAL_SERVER_ERROR;
    }

    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: uri.path=%s", uri.path);

    plpgsqlConfig *config = (plpgsqlConfig *)
        ap_get_module_config(r->per_dir_config, &plpgsql_module);

    if (strcmp(r->handler, "plpgsql-handler")) {
        return DECLINED;
    }

    if(config != NULL) {
        if (!config->enable) {
   	   ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: disabled");
           return DECLINED;
        }
    } else {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: no config");
        return DECLINED;
    }

    if (r->header_only) {
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: header only");
        return OK;
    }

    conninfo = apr_psprintf(r->pool, "host=%s port=%s dbname=%s user=%s password=%s", 
		                      config->hostname,
				      config->port,
				      config->dbname,
				      config->username,
				      config->password
				      );
    conn = PQconnectdb(conninfo);
    if (PQstatus(conn) == CONNECTION_BAD)
    {
    	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: %s", PQerrorMessage(conn));
	return HTTP_INTERNAL_SERVER_ERROR;
    }
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: connected to PG" );

    if (r->args != NULL)
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: r->args=%s",r->args);
    else
        ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: r->args=NULL");

    ap_args_to_table(r, &args);
    /*
     * procedure call syntax: /pg/<procedure>?<parm1>=<value1>&<parm2>=<value2>
     * all parameters of procedure must be character strings to build parameter list
     */
    proc = (char *)(uri.path + (4 * sizeof(char)));
    endofprocname = strchr(uri.path, '?');
    if (endofprocname != NULL)
	   proc[endofprocname - proc] = '\0'; 

    pg_call_statement = apr_psprintf(r->pool, "call %s(", proc);
    argc = 0;
    apr_table_do(plpgsql_cbf, r, args, NULL);
    pg_call_statement = apr_psprintf(r->pool, "%s)", pg_call_statement);

    /*
     * called procedure must write to a table because "raise notice" cannot be read with PQlib.
     */
    stmt = apr_psprintf(r->pool, "%s;select line from output order by id;", pg_call_statement);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: running %s ...", stmt );
    res = PQexec(conn, stmt);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: ... ended");
    pgstatus = PQresultStatus(res);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: pgstatus=%s", PQresStatus(pgstatus));
    /* 
     * we expect at least one row 
     * */
    if (pgstatus != PGRES_TUPLES_OK) {
    	    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: return error 500");
	    return HTTP_INTERNAL_SERVER_ERROR;
    }
    cmdstatus = PQcmdStatus(res);
    ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, r->server, "plpgsql_handler: cmdstatus=%s", cmdstatus);

    ap_set_content_type(r, "text/html");
    for ( i = 0; i < PQntuples(res); i++)
    {
	    value = PQgetvalue(res, i, 0);
	    ap_rputs(value, r);
    }
    PQclear(res); 
    PQfinish(conn);

    return OK;

}

static void register_hooks(apr_pool_t *p)
{
  ap_hook_handler(plpgsql_handler, NULL, NULL, APR_HOOK_LAST);
}

static const command_rec plpgsql_cmds[] = 
{
    AP_INIT_TAKE1("PGUsername", plpgsql_username, NULL, ACCESS_CONF,
                 "PostgreSQL user name"),
    AP_INIT_TAKE1("PGPassword", plpgsql_password, NULL, ACCESS_CONF,
                 "PostgreSQL password"),
    AP_INIT_TAKE1("PGHostname", plpgsql_hostname, NULL, ACCESS_CONF,
                 "PostgreSQL instance host name"),
    AP_INIT_TAKE1("PGPort", plpgsql_port, NULL, ACCESS_CONF,
                 "PostgreSQL instance port number"),
    AP_INIT_TAKE1("PGDatabase", plpgsql_dbname, NULL, ACCESS_CONF,
                 "PostgreSQL database name"),
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
