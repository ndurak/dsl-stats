#include <stdio.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <signal.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/queue.h>
#include <mysql/mysql.h>
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/types.h>
#include <strings.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <signal.h>

#define MAXCLIENT 10
#define MAX_NUM_OF_OIDS 48

int host_num = 0;
MYSQL * conn;


struct session {
    struct snmp_session *sess;		/* SNMP session data */
    u_long currentIfIndex;
    oid maxoid[MAX_OID_LEN];
    size_t maxoid_len;
    int try;
    TAILQ_ENTRY(session) entries;
};
  
int finished = 0;
int active_hosts;
int client_pids[MAXCLIENT];

struct oid {
    const char *oidName;
    const char *paramName;
    oid Oid[MAX_OID_LEN];
    size_t OidLen;
};

struct parameter {
    char oidname[64];
    char name[64];
    char value[30];
};

struct port {
    u_long ifIndex;
    struct parameter parameters[MAX_NUM_OF_OIDS];
    TAILQ_ENTRY(port) entries;
};


struct host {
    char name[64];
    char ip[20];
    char community[20];
    int type;
    short id;
    TAILQ_HEAD(port_head,port) ports;
    TAILQ_ENTRY(host) entries;
};

TAILQ_HEAD(list_head, host) host_head; 
TAILQ_HEAD(, session) session_head;

void start_xdsl_port_traversal(struct list_head);
int async_profile_resp(int, struct snmp_session *, int, struct snmp_pdu *, void *);
int async_line_resp(int, struct snmp_session *, int, struct snmp_pdu *, void *);
int async_chann_resp(int, struct snmp_session *, int, struct snmp_pdu *, void *);
                                                                    

struct oid ma5600t_xdsl_profile_oids[] = {
    {"1.3.6.1.4.1.2011.6.144.1.2.2.2.1.6", "data_rate_profile_ds_id"},    /* hwVOPSetupDsDataRateProfId1 */
    {"1.3.6.1.4.1.2011.6.144.1.2.2.2.1.4", "data_rate_profile_us_id"},    /* hwVOPSetupUsDataRateProfId1 */
    {"1.3.6.1.4.1.2011.6.144.1.2.2.2.1.28", "noise_margin_profile_id"},   /* hwVOPSetupNoiseMarginProfId */
    {"1.3.6.1.4.1.2011.6.144.1.2.2.2.1.24", "line_spectrum_profile_id"},   /* hwVOPSetupLSpectrumProfId */
    {"1.3.6.1.4.1.2011.6.144.1.2.2.2.1.8", "inp_profile_id"},    /* hwVOPSetupInpDelayProfId1 */
    {NULL}
};
struct oid ma5600t_adsl_line_oids[] = {
    {".1.3.6.1.2.1.10.238.1.1.1.1.9", "status"}, /*adsl2LineStatusInitResult*/
    {".1.3.6.1.2.1.10.238.1.1.1.1.14", "ln_atten_ds"}, /*adsl2LineStatusLnAttenDs*/
    {".1.3.6.1.2.1.10.238.1.1.1.1.15", "ln_atten_us"}, /*adsl2LineStatusSigAttenUs*/
    {".1.3.6.1.2.1.10.238.1.1.1.1.18", "snr_margin_ds"}, /*adsl2LineStatusSnrMarginDs*/
    {".1.3.6.1.2.1.10.238.1.1.1.1.19", "snr_margin_us"}, /*adsl2LineStatusSnrMarginUs*/
    {".1.3.6.1.2.1.10.238.1.1.1.1.24", "act_atp_ds"}, /*adsl2LineStatusActAtpDs*/
    {".1.3.6.1.2.1.10.238.1.1.1.1.25", "act_atp_us"}, /*adsl2LineStatusActAtoUs*/
    {".1.3.6.1.4.1.2011.6.138.1.1.1.1.7", "rtx_used_ds"}, /*LineStatusRtxUsedDs*/
    {".1.3.6.1.2.1.10.238.1.1.1.1.20", "attainable_rate_ds"}, /*adsl2LineStatusAttainableRateDs*/
    {".1.3.6.1.2.1.10.238.1.1.1.1.21", "attainable_rate_us"}, /*adsl2LineStatusAttainableRateUs*/
    {".1.3.6.1.4.1.2011.6.138.1.4.1.4.1.1", "init_times"}, /*hwadsl2PMLInitEverBeforeFullInits*/
    {NULL}
};
struct oid ma5600t_adsl_channel_oids[] = {
    {".1.3.6.1.2.1.10.238.1.2.1.1.3", "act_data_rate_"}, /*adsl2ChStatusActDataRate*/
    {".1.3.6.1.2.1.10.238.1.2.1.1.5", "act_delay_"}, /*adsl2ChStatusActDelay*/
    {".1.3.6.1.4.1.2011.6.138.1.2.1.1.3", "inp_"}, /*hwadsl2ChStatusINP*/
    {".1.3.6.1.4.1.2011.6.138.1.4.1.1.1.11", "es_"}, /*hwadsl2PMLEverBeforeEs*/
    {".1.3.6.1.4.1.2011.6.138.1.4.1.1.1.12", "ses_"}, /*hwadsl2PMLEverBeforeSes*/
    {NULL}
};
struct oid ma5600t_vdsl_line_oids[] = {
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.9", "status"},      /* vdsl2LineStatusInitResult */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.40", "modulation"},      /* vdsl2LineActMode */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.14", "ln_atten_ds"},     /* vdsl2LineStatusLnAttenDs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.15", "ln_atten_us"},     /* vdsl2LineStatusLnAttenUs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.41", "kl0_co"},     /* vdsl2UpboProfKl0CoVal */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.35", "kl0_cpe"},     /* vdsl2UpboProfKl0CpeVal */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.18", "snr_margin_ds"},     /* vdsl2LineStatusSnrMarginDs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.19", "snr_margin_us"},     /* vdsl2LineStatusSnrMarginUs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.24", "act_atp_ds"},     /* vdsl2LineStatusActAtpDs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.25", "act_atp_us"},     /* vdsl2LineStatusActAtpUs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.42", "rtx_used_ds"},     /* vdsl2LineStatusRtxUsedDs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.43", "rtx_used_us"},     /* vdsl2LineStatusRtxUsedUs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.54", "ra_mode_ds"},     /* hwvdsl2LineStatusActRaModeDs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.55", "ra_mode_us"},     /* hwvdsl2LineStatusActRaModeUs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.20", "attainable_rate_ds"},     /* vdsl2LineStatusAttainableRateDs */
    {"1.3.6.1.4.1.2011.6.115.1.1.1.1.21", "attainable_rate_us"},     /* vdsl2LineStatusAttainableRateUs */
    {"1.3.6.1.4.1.2011.6.115.1.4.1.2.1.11", "init_times"},   /* vdsl2PMLInitEverBeforeFullInits */
    {NULL}
};
struct oid ma5600t_vdsl_channel_oids[] = {
    {"1.3.6.1.4.1.2011.6.115.1.2.1.1.3", "act_data_rate_"},      /* vdsl2ChStatusActDataRateDS */
    {"1.3.6.1.4.1.2011.6.115.1.2.1.1.5", "act_delay_"},      /* vdsl2ChStatusActDelay */
    {"1.3.6.1.4.1.2011.6.115.1.2.1.1.8", "inp_"},      /* vdsl2ChStatusINP */
    {"1.3.6.1.4.1.2011.6.115.1.2.1.1.19", "inp_rein_"},     /* vdsl2ChStatusActINPAgainstREIN */
    {"1.3.6.1.4.1.2011.6.115.1.4.1.1.1.19", "es_"},   /* vdsl2PMLEverBeforeEs */
    {"1.3.6.1.4.1.2011.6.115.1.4.1.1.1.20", "ses_"},   /* vdsl2PMLEverBeforeSes */
    {NULL}
};

/*
 * This function will find dslam's in database, and create linked list
 * of dslam's with head pointing to head and tail of dslam list.
 */
int getDslams(MYSQL * conn) 
{
    MYSQL_RES *result;
    MYSQL_ROW row;
    struct host *dslam;
    mysql_query(conn, "select name, ip, dslam_id, dslam_type_id from dslams where dslam_type_id in (2,3,4,5)");
    result = mysql_store_result(conn);
    while((row = mysql_fetch_row(result))) {
	if(strlen(row[1]) >= 7) {
	    dslam = malloc(sizeof(*dslam));
	    strcpy(dslam->name, row[0]);
	    strcpy(dslam->ip, row[1]);
	    strcpy(dslam->community, "public");
            dslam->type = atoi(row[4]);
            dslam->id = atoi(row[2]);
	    TAILQ_INIT(&dslam->ports);
	    TAILQ_INSERT_TAIL(&host_head, dslam, entries);
	    host_num++;
	}
    }
    mysql_free_result(result);
    return 0;
}

/*
 * type: 0 - adsl, 1 - vdsl_chan, 2 - vdsl_line
 */
long hash_index(unsigned int ifIndex) {
    unsigned int start, index;
    if(ifIndex >= 4160749568U) {
    /* vdsl line ifIndex */
        start = 4160749568U;
    } else if(ifIndex >= 4127195137U) {
    /* vdsl chann ifIndex */
        start = 4127195137U;
    } else if(ifIndex >= 201326592U) {
    /* adsl ifIndex */
        start = 201326592U;
    }
    index = ((ifIndex - start) >> 13) * 64 + (((ifIndex - start) % 8192) >> 6);
    return index;
}

u_long calcChannIfIndex(u_long ifIndex) {
    u_long dif;
    if (ifIndex >= 4160749568U) {
        dif = 33554431;
        return ifIndex - dif;
    } else if (ifIndex >= 201326592U) {
        dif = 3925868545U;
        return ifIndex + dif;
    } else {
        return 0;
    }
}

void build_struct_oid(struct oid *op) {
    /* initialize library */
    init_snmp("dslam-snmp1");
    while(op->oidName) {
        op->OidLen = sizeof(op->Oid)/sizeof(op->Oid[0]);
        if(!read_objid(op->oidName, op->Oid, &op->OidLen)) {
            snmp_perror("read objid");
            exit(1);
        }
        op++;
    }
}

void getMaxoid(struct oid *op, oid *maxoid, size_t *maxoid_len) {
    while(op->oidName) {
        if(maxoid == NULL) {
            memmove(maxoid, op->Oid, sizeof(oid)*MAX_OID_LEN);
            *maxoid_len = op->OidLen;
        } else {
            if(snmp_oid_compare(maxoid, *maxoid_len, op->Oid, op->OidLen) < 0) {
                memmove(maxoid, op->Oid, sizeof(oid)*MAX_OID_LEN);
                *maxoid_len = op->OidLen;
            }
        }
        op++;
    }
}

void initialize_oids (void)
{
    /* Win32: init winsock */
    SOCK_STARTUP;

    build_struct_oid(ma5600t_xdsl_profile_oids); 
    build_struct_oid(ma5600t_vdsl_line_oids);
    build_struct_oid(ma5600t_vdsl_channel_oids);
    build_struct_oid(ma5600t_adsl_line_oids);
    build_struct_oid(ma5600t_adsl_channel_oids);
}

void initialize(MYSQL * conn) 
{
    TAILQ_INIT(&host_head);
    if(!mysql_real_connect(conn, "mydb.myorg.net","user", "pw",
        "dslstatsdb", 0, NULL, 0)) {
	fprintf(stderr,"Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
	mysql_close(conn);
	exit(1);
    }
    getDslams(conn);
    initialize_oids();
}


int save_result (netsnmp_session *sp, netsnmp_variable_list *vars,
    u_long ifIndex, int j) 
{
    struct port *port = NULL;
    netsnmp_variable_list *var;
    struct host *this_host;
    int  i, k;
    u_long index;

    TAILQ_FOREACH(this_host, &host_head, entries) {
        if(strcmp(this_host->ip, sp->peername) == 0) {
            break;
        }
    }

    index = hash_index(ifIndex);
    i = index % 64;
    if(j == 0) {
    /* first set of variables */
        if(i == 0) {
        /* first port on board / new board, malloc for new board */
            port = (struct port *) malloc(sizeof(struct port) * 64);
            if(port == NULL) { 
                perror("port is null");
                exit(1);
            } 
        } else {
            port = TAILQ_LAST(&this_host->ports, port_head);
            port++;
        }
        port->ifIndex = ifIndex;
        TAILQ_INSERT_TAIL(&this_host->ports, port, entries);
        for(var = vars; var; var = var->next_variable) {
            strcpy(port->parameters[j].name,ma5600t_xdsl_profile_oids[j].paramName);
            snprint_value(port->parameters[j].value, sizeof(port->parameters[j].value), \
                var->name, var->name_length, var);
            snprint_objid(port->parameters[j].oidname, sizeof(port->parameters[j].oidname), \
                var->name, var->name_length - 1);
            j++;
        }
    } else if (j == sizeof(ma5600t_xdsl_profile_oids) / sizeof(struct oid) - 1) {
        port = TAILQ_LAST(&this_host->ports, port_head);
        for(var = vars; var; var = var->next_variable) {
            k = j - sizeof(ma5600t_xdsl_profile_oids) / sizeof(struct oid) + 1;
            if (ifIndex >= 201326592 && ifIndex <= 201478080) {
                strcpy(port->parameters[j].name,ma5600t_adsl_line_oids[k].paramName);
            } else if (ifIndex >= 4160749568U && ifIndex <= 4160901056U) {
                strcpy(port->parameters[j].name,ma5600t_vdsl_line_oids[k].paramName);
            }
            if (*var->val.integer == 4294967295U) {
                sprintf(port->parameters[j].value, "0.0");
            } else if(*var->val.integer == 2147483647U) {
                sprintf(port->parameters[j].value, "0.0");
            } else if(strncmp(port->parameters[j].name, "ln_att", 5) == 0) {
		sprintf(port->parameters[j].value, "%.1f", (float) *var->val.integer/10.0);
            } else if (strncmp(port->parameters[j].name, "kl0", 3) == 0) {
                sprintf(port->parameters[j].value, "%.1f", (float) *var->val.integer/10.0);
            } else if (strncmp(port->parameters[j].name, "snr", 3) == 0) {
                sprintf(port->parameters[j].value, "%.1f",(float) *var->val.integer/10.0);
            } else if (strncmp(port->parameters[j].name, "act",3) == 0) {
                sprintf(port->parameters[j].value, "%.1f",(float) *var->val.integer/10.0);
            } else if (strncmp(port->parameters[j].name, "attain", 6) == 0) {
                sprintf(port->parameters[j].value, "%ld", *var->val.integer/1000);
            } else {
                snprint_value(port->parameters[j].value, sizeof(port->parameters[j].value), \
                    var->name, var->name_length, var);
            }
            snprint_objid(port->parameters[j].oidname, sizeof(port->parameters[j].oidname), \
                var->name, var->name_length - 1);
            j++; 
        }
    } else {
        port = TAILQ_LAST(&this_host->ports, port_head);
        for(var = vars; var; var = var->next_variable) {
            if (ifIndex >= 201326592U && ifIndex <= 201478080U) {
                k = j - (sizeof(ma5600t_xdsl_profile_oids) + 
                    sizeof(ma5600t_adsl_line_oids)) / sizeof(struct oid) + 2;
                if (k >= sizeof(ma5600t_adsl_channel_oids)/sizeof(struct oid) - 1) {
                    k -= sizeof(ma5600t_adsl_channel_oids)/sizeof(struct oid) - 1;
                    strcpy(port->parameters[j].name, ma5600t_adsl_channel_oids[k].paramName);
                    if (strncmp(port->parameters[j].name, "ses",3) == 0 || strncmp(port->parameters[j].name, "es",2) == 0)
                        strcat(port->parameters[j].name, "ds");
                    else 
                        strcat(port->parameters[j].name, "us");
                } else {
                    strcpy(port->parameters[j].name, ma5600t_adsl_channel_oids[k].paramName);
                    if (strncmp(port->parameters[j].name, "ses",3) == 0 || strncmp(port->parameters[j].name, "es",2) == 0)
                        strcat(port->parameters[j].name, "us");
                    else 
                        strcat(port->parameters[j].name, "ds");
                }
             } else if (ifIndex >= 4160749568U && ifIndex <= 4160901056U) {
                k = j - (sizeof(ma5600t_xdsl_profile_oids) +
                    sizeof(ma5600t_vdsl_line_oids)) / sizeof(struct oid) + 2;
                if (k >= sizeof(ma5600t_vdsl_channel_oids)/sizeof(struct oid) - 1) {
                    k -= sizeof(ma5600t_vdsl_channel_oids)/sizeof(struct oid) - 1;
                    strcpy(port->parameters[j].name, ma5600t_vdsl_channel_oids[k].paramName);
                    if (strncmp(port->parameters[j].name, "ses",3) == 0 || strncmp(port->parameters[j].name, "es",2) == 0)
                        strcat(port->parameters[j].name, "ds");
                    else 
                        strcat(port->parameters[j].name, "us");
                } else {
                    strcpy(port->parameters[j].name, ma5600t_vdsl_channel_oids[k].paramName);
                    if (strncmp(port->parameters[j].name, "ses",3) == 0 || strncmp(port->parameters[j].name, "es",2) == 0)
                        strcat(port->parameters[j].name, "us");
                    else 
                        strcat(port->parameters[j].name, "ds");
                }
            }
            if (*var->val.integer == 4294967295U) {
                sprintf(port->parameters[j].value, "0.0");
            } else if(*var->val.integer == 2147483647U) {
                sprintf(port->parameters[j].value, "0.0");
            } else if(strncmp(port->parameters[j].name, "inp", 3) == 0) {
                sprintf(port->parameters[j].value, "%.1f", (float) *var->val.integer/10.0);
            } else if(strncmp(port->parameters[j].name, "act_data", 8) == 0) {
                sprintf(port->parameters[j].value, "%ld", *var->val.integer/1000);
            } else {
                snprint_value(port->parameters[j].value, sizeof(port->parameters[j].value), \
                    var->name, var->name_length, var);
            }
            snprint_objid(port->parameters[j].oidname, sizeof(port->parameters[j].oidname), \
                var->name, var->name_length - 1);
            j++; 
        }
    }
    return 0;
}



void save_into_db2(struct host *this_host) 
{
    struct port *this_port;
    int i, j;
    char query[16000];
    char query_param[512];
    char query_values[15500];
    char query_tmp[60];
    j = 0;
    TAILQ_FOREACH(this_port, &this_host->ports, entries) {
        if(j % 64 == 0) {
            bzero(query_param, sizeof(char)*512);
            bzero(query_values, sizeof(char)*15500);
            sprintf(query_param, "dslam_id,port_id");
            sprintf(query_values, "(%d,(select id from ports where ifIndex=%lu),", this_host->id, this_port->ifIndex);
        } else {
            sprintf(query_tmp, ",(%d,(select id from ports where ifIndex=%lu),", this_host->id, this_port->ifIndex);
            strcat(query_values, query_tmp);
        }
        i = 0;
        while(this_port->parameters[i].oidname[0]) {
            if (j % 64 == 0) {
                strcat(query_param, ",");
                strcat(query_param, this_port->parameters[i].name);
            }
            if(i > 0) 
                strcat(query_values, ",");
            strcat(query_values, this_port->parameters[i].value);
            i++;
        }
        if (this_port->entries.tqe_next == NULL || j % 64 == 63) {
        /* zadnji port na kartici, izvrsi query */
            strcat(query_values, ")");
            if(this_port->ifIndex >= 4160749568U) {
                sprintf(query, "insert into vdsl_stats (%s) values %s", query_param, query_values);
            } else if (this_port->ifIndex <= 201478080U) {
                sprintf(query, "insert into adsl_stats (%s) values %s", query_param, query_values);
            }
            fprintf(stderr, "%s\n", query);
            if(mysql_query(conn, query)) {
                fprintf(stderr, "Error %s\n", mysql_error(conn));
            }
        } else if (j % 64 != 63) {
            strcat(query_values, ")");
        }
        j++;
    }
}           
    


int async_chann_resp(int operation, struct snmp_session *sp, int reqid,
                        struct snmp_pdu *response, void *magic)
{
    struct session *mysess = (struct session *) magic;
    netsnmp_pdu *req;
/*    netsnmp_variable_list *vars; */
    u_long ifIndex;
    oid maxoid[MAX_OID_LEN];
    size_t maxoid_len, oid_len;
    int i;
    i = 0;

    if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
        mysess->try = 0;
        if (response->errstat == SNMP_ERR_NOERROR) {
            ifIndex = mysess->currentIfIndex;
            req = snmp_pdu_create(SNMP_MSG_GETNEXT);
            getMaxoid(ma5600t_adsl_channel_oids, maxoid, &maxoid_len);
            mysess->sess->callback = async_profile_resp;
            while(ma5600t_xdsl_profile_oids[i].oidName) {
                oid_len = ma5600t_xdsl_profile_oids[i].OidLen;
                ma5600t_xdsl_profile_oids[i].Oid[oid_len] = ifIndex;
                snmp_add_null_var(req, ma5600t_xdsl_profile_oids[i].Oid, oid_len+1);
                i++;
            }
            if (snmp_send(mysess->sess, req) == 0) {
                snmp_perror("snmp_send");
                snmp_free_pdu(req);
            }
            if (ifIndex >= 201326592U && ifIndex <= 201478080U) {
                save_result(sp, response->variables, ifIndex,(sizeof(ma5600t_xdsl_profile_oids)
                    + sizeof(ma5600t_adsl_line_oids)) / sizeof(struct oid) - 2);
            } else if (ifIndex >= 4160749568U && ifIndex <= 4160901056U) { 
                save_result(sp, response->variables, ifIndex,(sizeof(ma5600t_xdsl_profile_oids)
                    + sizeof(ma5600t_vdsl_line_oids)) / sizeof(struct oid) - 2);
            }
       /* log errors in response */
	} else if (response->errstat == SNMP_ERR_TOOBIG) { 
            fprintf(stderr,"snmp err too big\n");
	} else if (response->errstat == SNMP_ERR_BADVALUE) {
            fprintf(stderr, "snmp err badvalue\n");
	} else {
            fprintf(stderr, "snmp error\n");
	}
    }
    else if (operation == NETSNMP_CALLBACK_OP_TIMED_OUT) { 
        /* timeout, resend */
        u_long ifIndex2;
        fprintf(stderr, "Async timeout %s\n", mysess->sess->peername);
        sleep(1);
        (mysess->try)++;
        ifIndex = mysess->currentIfIndex;
        if(mysess->try < 3) {
            i = 0;
            ifIndex2 = calcChannIfIndex(ifIndex);
            req = snmp_pdu_create(SNMP_MSG_GETBULK);
            req->non_repeaters = 0;
            req->max_repetitions = 2;
            if (ifIndex >= 201326592U && ifIndex <= 201478080U) {
                while(ma5600t_adsl_channel_oids[i].oidName) {
                    oid_len = ma5600t_adsl_channel_oids[i].OidLen;
                    ma5600t_adsl_channel_oids[i].Oid[oid_len] = ifIndex2;
                    snmp_add_null_var(req, ma5600t_adsl_channel_oids[i].Oid, oid_len+1);
                    i++;
                } 
            } else if (ifIndex >= 4160749568U && ifIndex <= 4160901056U) {
                while(ma5600t_vdsl_channel_oids[i].oidName) {
                    oid_len = ma5600t_vdsl_channel_oids[i].OidLen;
                    ma5600t_vdsl_channel_oids[i].Oid[oid_len] = ifIndex2;
                    snmp_add_null_var(req, ma5600t_vdsl_channel_oids[i].Oid, oid_len+1);
                    i++;
                } 
            }
            if (snmp_send(mysess->sess, req) == 0) {
                snmp_perror("snmp_send");
                snmp_free_pdu(req);
            }
        } else {
            fprintf(stderr, "Host %s timeout error on async_chann_resp; ifIndex=%lu",mysess->sess->peername, ifIndex);
            active_hosts--;
        }
    } else 
        fprintf(stderr, "operation = %d \n", operation);
    return 1;
}

int async_line_resp(int operation, struct snmp_session *sp, int reqid,
                        struct snmp_pdu *response, void *magic)
{
    struct session *mysess = (struct session *) magic;
    netsnmp_pdu *req;
    netsnmp_variable_list *vars;
    u_long ifIndex, ifIndex2;
    oid maxoid[MAX_OID_LEN];
    size_t maxoid_len, oid_len;
    int i;
    i = 0;

    if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
        mysess->try = 0;
        if (response->errstat == SNMP_ERR_NOERROR) {
            vars = response->variables;
            ifIndex = vars->name[vars->name_length - 1];
            ifIndex2 = calcChannIfIndex(ifIndex);
            if (ifIndex >= 201326592U && ifIndex <= 201478080U) {
            /* send adsl channel snmp req */
                req = snmp_pdu_create(SNMP_MSG_GETBULK);
                req->non_repeaters = 0;
                req->max_repetitions = 2;
                getMaxoid(ma5600t_adsl_channel_oids, maxoid, &maxoid_len);
                mysess->sess->callback = async_chann_resp;
                while(ma5600t_adsl_channel_oids[i].oidName) {
                    oid_len = ma5600t_adsl_channel_oids[i].OidLen;
                    ma5600t_adsl_channel_oids[i].Oid[oid_len] = ifIndex2;
                    snmp_add_null_var(req, ma5600t_adsl_channel_oids[i].Oid, oid_len+1);
                    i++;
                } 
            } else if (ifIndex >= 4160749568U && ifIndex <= 4160901056U) {
            /* send vdsl channel snmp req */
                req = snmp_pdu_create(SNMP_MSG_GETBULK);
                req->non_repeaters = 0;
                req->max_repetitions = 2;
                getMaxoid(ma5600t_vdsl_channel_oids, maxoid, &maxoid_len);
                mysess->sess->callback = async_chann_resp;
                while(ma5600t_vdsl_channel_oids[i].oidName) {
                    oid_len = ma5600t_vdsl_channel_oids[i].OidLen;
                    ma5600t_vdsl_channel_oids[i].Oid[oid_len] = ifIndex2;
                    snmp_add_null_var(req, ma5600t_vdsl_channel_oids[i].Oid, oid_len+1);
                    i++;
                } 
            }         
            if (snmp_send(mysess->sess, req) == 0) {
                snmp_perror("snmp_send");
                snmp_free_pdu(req);
            }
            save_result(sp, response->variables, ifIndex, 
                sizeof(ma5600t_xdsl_profile_oids) / sizeof(struct oid) - 1); 
       /* log if err in response */
	} else if (response->errstat == SNMP_ERR_TOOBIG) { 
            fprintf(stderr, "snmp err too big\n");
	} else if (response->errstat == SNMP_ERR_BADVALUE) {
            fprintf(stderr, "snmp err badvalue\n");
	} else {
            fprintf(stderr, "snmp error\n");
	}
    }
    else if (operation == NETSNMP_CALLBACK_OP_TIMED_OUT) { 
        /* timeout, resend */
        fprintf(stderr, "Async timeout %s\n", mysess->sess->peername);
        sleep(1);
        (mysess->try)++;
        ifIndex = mysess->currentIfIndex;
        if(mysess->try < 3) {
            i = 0;
            req = snmp_pdu_create(SNMP_MSG_GET);
            if (ifIndex >= 201326592U && ifIndex <= 201478080U) {
                /* send queries for adsl board
                */
                while(ma5600t_adsl_line_oids[i].oidName) {
                    oid_len = ma5600t_adsl_line_oids[i].OidLen; 
                    ma5600t_adsl_line_oids[i].Oid[oid_len] = ifIndex;
                    snmp_add_null_var(req, ma5600t_adsl_line_oids[i].Oid, oid_len+1);
                    i++;
                }
            } else if (ifIndex >= 4160749568U && ifIndex <= 4160901056U) {
            /* send vdsl line snmp req */
                while(ma5600t_vdsl_line_oids[i].oidName) {
                    oid_len = ma5600t_vdsl_line_oids[i].OidLen;
                    ma5600t_vdsl_line_oids[i].Oid[oid_len] = ifIndex;
                    snmp_add_null_var(req, ma5600t_vdsl_line_oids[i].Oid, oid_len+1);
                    i++;
                }
            }
            if (snmp_send(mysess->sess, req) == 0) {
                snmp_perror("snmp_send");
                snmp_free_pdu(req);
            }
        } else {
            fprintf(stderr, "Host %s timeout error on async_line_resp; ifIndex=%lu",mysess->sess->peername, ifIndex);
            active_hosts--;
        }
    } else 
        fprintf(stderr, "operation = %d \n", operation);
    return 1;
}


 
int async_profile_resp(int operation, struct snmp_session *sp, int reqid,
                        struct snmp_pdu *response, void *magic)
{
    struct session *mysess = (struct session *) magic;
    netsnmp_pdu *req;
    netsnmp_variable_list *vars;
    u_long ifIndex;
    oid maxoid[MAX_OID_LEN];
    struct host *host;
    size_t maxoid_len, oid_len;
    int i = 0;

    if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) {
        mysess->try = 0;
        if (response->errstat == SNMP_ERR_NOERROR) {
/* Traverse all vars in response, and if anyone is greather than maxoid,
 * we stop. maxoid is greather than any var in oid_group_entry->oids set. 
 */
            vars = response->variables;
            ifIndex = vars->name[vars->name_length - 1];
            if (ifIndex < mysess->currentIfIndex) {
            /* we have collected all the vars */
                TAILQ_FOREACH(host, &host_head, entries) {
                    if(strcmp(host->ip, sp->peername) == 0) {
                        break;
                    }
                }
                save_into_db2(host);
                active_hosts--;
                return 1;
            }
            /* if ADSL
             * 0/0/0 = 201326592, 0/18/63 = 201478080 
             */
            if (ifIndex >= 201326592U && ifIndex <= 201478080U) {
                /* send queries for adsl board
                */
                req = snmp_pdu_create(SNMP_MSG_GET);
                getMaxoid(ma5600t_adsl_line_oids, maxoid, &maxoid_len);
                mysess->currentIfIndex = ifIndex;
                mysess->sess->callback = async_line_resp;
                while(ma5600t_adsl_line_oids[i].oidName) {
                    oid_len = ma5600t_adsl_line_oids[i].OidLen; 
                    ma5600t_adsl_line_oids[i].Oid[oid_len] = ifIndex;
                    snmp_add_null_var(req, ma5600t_adsl_line_oids[i].Oid, oid_len+1);
                    i++;
                }
            } else if (ifIndex >= 4160749568U && ifIndex <= 4160901056U) {
            /* send vdsl line snmp req */
                req = snmp_pdu_create(SNMP_MSG_GET);
                getMaxoid(ma5600t_vdsl_line_oids, maxoid, &maxoid_len);
                mysess->currentIfIndex = ifIndex;
                mysess->sess->callback = async_line_resp;
                while(ma5600t_vdsl_line_oids[i].oidName) {
                    oid_len = ma5600t_vdsl_line_oids[i].OidLen;
                    ma5600t_vdsl_line_oids[i].Oid[oid_len] = ifIndex;
                    snmp_add_null_var(req, ma5600t_vdsl_line_oids[i].Oid, oid_len+1);
                    i++;
                }
                i = 0;
            }
            netsnmp_ds_set_boolean(NETSNMP_DS_LIBRARY_ID, NETSNMP_DS_LIB_QUICK_PRINT, 1);
            if (snmp_send(mysess->sess, req) == 0) {
                snmp_perror("snmp_send");
                snmp_free_pdu(req);
            }
            save_result(sp, response->variables, ifIndex, 0); 
	} else if (response->errstat == SNMP_ERR_TOOBIG) { 
            fprintf(stderr, "snmp err too big\n");
	} else if (response->errstat == SNMP_ERR_BADVALUE) {
            fprintf(stderr, "snmp err badvalue\n");
	} else {
            fprintf(stderr, "snmp error\n");
	}
    }
    else if (operation == NETSNMP_CALLBACK_OP_TIMED_OUT) { 
        fprintf(stderr, "Async timeout %s\n", mysess->sess->peername);
        sleep(1);
        (mysess->try)++;
        if(mysess->try < 3) {
            i = 0;
            req = snmp_pdu_create(SNMP_MSG_GETNEXT);
            while (ma5600t_xdsl_profile_oids[i].oidName) {
                oid_len = ma5600t_vdsl_line_oids[i].OidLen;
                if(mysess->currentIfIndex > 0) {
                    ma5600t_xdsl_profile_oids[i].Oid[oid_len] = mysess->currentIfIndex;
                    snmp_add_null_var(req, ma5600t_xdsl_profile_oids[i].Oid, oid_len + 1);
                } else {
                    snmp_add_null_var(req, ma5600t_xdsl_profile_oids[i].Oid, oid_len);
                }
                i++;
            }
            if (snmp_send(mysess->sess, req) == 0) {
                snmp_perror("snmp_send");
                snmp_free_pdu(req);
            }
        } else {
            if(mysess->currentIfIndex ==0) {
                fprintf(stderr, "Host %s unavailable\n", mysess->sess->peername);
            } else {
                fprintf(stderr, "Host %s timeout error; ifIndex=%lu",mysess->sess->peername, mysess->currentIfIndex);
            }
            active_hosts--;
        }
    } else 
        fprintf(stderr,"operation = %d \n", operation);
    /* something went wrong (or end of variables) 
     * THIS HOST NOT active any more
    */
    return 1;
}

void start_xdsl_port_traversal(struct list_head host_head)
{
    struct session *mysess;
    struct host *this_host;
    struct snmp_pdu *req;
    struct snmp_session sess;
    int i;
    oid maxoid[MAX_OID_LEN];
    size_t maxoid_len;
    TAILQ_INIT(&session_head);
    TAILQ_FOREACH(this_host, &host_head, entries) {
        TAILQ_INIT(&this_host->ports);
        i = 0;
        mysess = (struct session *) malloc(sizeof(*mysess));
        snmp_sess_init(&sess);			/* initialize session */
        sess.version = SNMP_VERSION_2c;
        sess.peername = strdup(this_host->ip);
        sess.community = (u_char *) strdup(this_host->community);
        sess.community_len = (int) strlen(this_host->community);
        sess.retries = 1;
        sess.timeout = 1500000;
        sess.callback = async_profile_resp;		/* default callback */
        sess.callback_magic = mysess;
        if (!(mysess->sess = snmp_open(&sess))) {
            snmp_perror("snmp_open");
        }
        req = snmp_pdu_create(SNMP_MSG_GETNEXT);
        getMaxoid(ma5600t_xdsl_profile_oids, maxoid, &maxoid_len);
        memmove(mysess->maxoid, maxoid, sizeof(oid)*MAX_OID_LEN);
        mysess->maxoid_len = MAX_OID_LEN;
        mysess->currentIfIndex = 0;
        while (ma5600t_xdsl_profile_oids[i].oidName) {
            snmp_add_null_var(req, ma5600t_xdsl_profile_oids[i].Oid, ma5600t_xdsl_profile_oids[i].OidLen);
            i++;
        }
        if (snmp_send(mysess->sess, req) == 0) {
            snmp_perror("snmp_send");
            snmp_free_pdu(req);
        } else {
            active_hosts++;
        }
        printf("Process %d, dslam=%s, active_host=%d\n", getpid(), this_host->name, active_hosts);
    }
}


void worker_run(struct list_head host_head)
{
    start_xdsl_port_traversal(host_head);
    while (active_hosts > 0) {
        int fds = 0, block = 1;
        fd_set fdset;
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        FD_ZERO(&fdset);
        snmp_select_info(&fds, &fdset, &timeout, &block);
        fds = select(fds, &fdset, NULL, NULL, block ? NULL : &timeout);
        if (fds < 0) {
            perror("select failed");
            exit(1);
        }
        if (fds) {
            snmp_read(&fdset);
        } else {
            snmp_timeout(); 
        }
    }
}

/* Client processes are getting dslams from which they are collecting data by
   reading pipe where mng process has sent dslam data.
*/
int worker_body (int fd) {
    struct host *dslam;
    TAILQ_INIT(&host_head);
    int i = 0;
    size_t s;
    int maxHostPerProc = host_num / MAXCLIENT + 1;
    dslam = (struct host *) malloc(sizeof(struct host) * maxHostPerProc);
    do {
        s = read(fd, &dslam[i], sizeof(struct host));
        if (s < 0) {
            if (errno == EINTR)
                s = 0;
            else {
                printf("Function is interupted by %d\n", errno);
                exit(1);
            }
        } else if (s == 0) { 
            close(fd);
            break;
        }
        TAILQ_INSERT_TAIL(&host_head, &dslam[i], entries);
        i++;
    } while (s && i < maxHostPerProc);
    /* Start the work */
    worker_run(host_head);
    return 0;
}
        
int mng_process(int fd) 
{
    struct host *dslam;
    TAILQ_FOREACH(dslam, &host_head, entries) {
        write(fd, dslam, sizeof(struct host));
    }
    close(fd);
    return 0;
}

int main(int argc, char *argv[]) {
    int i, child_num, status;
    int fd[2];
    pid_t p, pp;
    printf("Initializing data\n");
    conn = mysql_init(NULL);
    if(conn == NULL) {
        printf("Error %u: %s\n", mysql_errno(conn), mysql_error(conn));
        exit(1);
    }

    initialize(conn);

    if (host_num < MAXCLIENT)
        child_num = host_num;
    else
        child_num = MAXCLIENT;

    if (pipe(fd) < 0) { 
        perror("pipe error");
        exit(1);
    }
/* Fork mng process. Mng process will feed client process with dslams */
    p = fork();
    if(p == 0) {
        close(fd[0]);
        mng_process(fd[1]);
        exit(0);
    } else if (p < 0) {
        exit(1);
    }
    close(fd[1]);
    sleep(1);
    pp = p;
/* Fork child_num worker processes. */
    for(i = 0; i < child_num; i++) {
        p = fork();
        if (p < 0) {
            client_pids[i] = p;
            exit(1);
        } else if (p == 0) {
            close(fd[1]);
            client_pids[i] = p;
            worker_body(fd[0]);
            exit(0);
        }
    }
    for(i = 0; i <= child_num; i++) {
        wait(&status);
    }
    kill(pp, SIGTERM);
    mysql_close(conn);
    return 0;
}

