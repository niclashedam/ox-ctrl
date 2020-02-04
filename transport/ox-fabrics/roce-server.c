/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (server side)
 *
 * Copyright 2018 IT University of Copenhagen
 *
 * Written by Ivan Luiz Picoli <ivpi@itu.dk>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <sched.h>
#include <errno.h>
#include <ox-fabrics.h>
#include <libox.h>

#include <rdma/rdma_cma.h>
#include <rdma/rsocket.h>

/* Last connection ID that has received a 'connect' command */
uint16_t pending_conn;

static struct oxf_server_con *oxf_roce_server_bind (struct oxf_server *server,
                                uint16_t cid, const char *addr, uint16_t port)
{
    struct oxf_server_con *con;

    if (cid > OXF_SERVER_MAX_CON) {
        log_err ("[ox-fabrics (bind): Invalid connection ID: %d]", cid);
        return NULL;
    }

    if (server->connections[cid]) {
        log_err ("[ox-fabrics (bind): Connection already established: %d]", cid);
        return NULL;
    }

    con = ox_malloc (sizeof (struct oxf_server_con), OX_MEM_TCP_SERVER);
    if (!con)
	return NULL;

    con->cid = cid;
    con->server = server;
    con->running = 0;
    memset (con->active_cli, 0x0, OXF_SERVER_MAX_CON * sizeof (int));

    if ( (con->sock_fd = rsocket(AF_INET, SOCK_STREAM, 0)) < 0 ) {
        log_err ("[ox-fabrics (bind): Socket creation failure. %d]", con->sock_fd);
        ox_free (con, OX_MEM_TCP_SERVER);
        return NULL;
    }

    con->addr.sin_family = AF_INET;
    inet_aton (addr, (struct in_addr *) &con->addr.sin_addr.s_addr);
    con->addr.sin_port = htons(port);

    int val = 8;
    rsetsockopt(con->sock_fd, SOL_RDMA, RDMA_IOMAPSIZE, (void *) &val, sizeof val);

    if ( rbind(con->sock_fd, (const struct sockaddr *) &con->addr,
                					sizeof(con->addr)) < 0 )
    {
        log_err ("[ox-fabrics (bind): Socket bind failure.]");
        goto ERR;
    }

    /* Put the socket in listen mode to accepting connections */
    if (rlisten (con->sock_fd, 16)) {
        log_err ("[ox-fabrics (bind): Socket listen failure.]");
        goto ERR;
    }

    server->connections[cid] = con;
    server->n_con++;

    memcpy (con->haddr.addr, addr, 15);
    con->haddr.addr[15] = '\0';
    con->haddr.port = port;

    return con;

ERR:
    rshutdown (con->sock_fd, 2);
    rclose (con->sock_fd);
    ox_free (con, OX_MEM_TCP_SERVER);
    return NULL;
}

static void oxf_roce_server_unbind (struct oxf_server_con *con)
{
    if (con) {
        rshutdown (con->sock_fd, 0);
        rclose (con->sock_fd);
        con->server->connections[con->cid] = NULL;
        con->server->n_con--;
        ox_free (con, OX_MEM_TCP_SERVER);
    }
}

static void *oxf_roce_server_con_th (void *arg)
{
    struct oxf_server_con *con = (struct oxf_server_con *) arg;
    uint16_t conn_id = pending_conn;
    uint32_t msg_bytes = 0;

    /* Set thread affinity, if enabled */
#if OX_TH_AFFINITY
    cpu_set_t cpuset;
    pthread_t current_thread;

    CPU_ZERO(&cpuset);
    CPU_SET(1, &cpuset);
    CPU_SET(2, &cpuset);
    CPU_SET(3, &cpuset);
    CPU_SET(7, &cpuset);

    current_thread = pthread_self();
    pthread_setaffinity_np(current_thread, sizeof(cpu_set_t), &cpuset);

    log_info (" [roce: Thread affinity is set for connection %d\n", con->cid);
#endif /* OX_TH_AFFINITY */

    pending_conn = 0;
    log_info ("[ox-fabrics: Connection %d is started -> client %d\n",
                                            conn_id, con->active_cli[conn_id]);

    con->buffer = aligned_alloc(4096, OXF_MAX_DGRAM + 1);
    con->local_offset = riomap(con->active_cli[conn_id] - 1, con->buffer, OXF_MAX_DGRAM + 1, PROT_WRITE, 0, -1);
    if(con->local_offset == -1){
        perror("Failed to register RIO buffer");
        return NULL;
    }

    int ret = rrecv(con->active_cli[conn_id] - 1, &con->remote_offset, sizeof(con->remote_offset), MSG_WAITALL);
    if (ret != sizeof(con->remote_offset)){
        printf ("[ox-fabrics: Failed to receive RIO memory region.]\n");
        perror("RIO receive error");
        return NULL;
    }

    ret = rsend(con->active_cli[conn_id] - 1, &con->local_offset, sizeof(con->local_offset), 0);
    if (ret != sizeof(con->local_offset)){
        printf ("[ox-fabrics: Failed to send RIO memory region.]\n");
        perror("RIO send error");
        return NULL;
    }

    log_info("[ox-fabrics: Local RIO offset is %ld]", con->local_offset);
    log_info("[ox-fabrics: Remote RIO offset is %ld]", con->remote_offset);

    printf("[ox-fabrics: Local RIO offset is %ld]\n", con->local_offset);
    printf("[ox-fabrics: Remote RIO offset is %ld]\n", con->remote_offset);

    while (con->active_cli[conn_id] > 0) {

        ret = rrecv(con->active_cli[conn_id] - 1,
                                            &msg_bytes, sizeof(msg_bytes), MSG_DONTWAIT);
        if (ret <= 0)
            continue;

        con->buffer[msg_bytes] = '\0';

        /* Timeout */
        if (msg_bytes < 0)
            continue;

        /* Client disconnected */
        if (msg_bytes == 0)
            break;

        con->rcv_fn (msg_bytes, (void *) con->buffer, (void *) (void *) &con->active_cli[conn_id]);
	msg_bytes = 0;
    }

    rclose (con->active_cli[conn_id] - 1);
    con->active_cli[conn_id] = 0;
    log_info ("[ox-fabrics: Connection %d is closed.]", conn_id);

    return NULL;
}

static void *oxf_roce_server_accept_th (void *arg)
{
    struct oxf_server_con *con = (struct oxf_server_con *) arg;
    struct sockaddr_in client;
    int client_sock;
    unsigned int len;

    len = sizeof (struct sockaddr);

    log_info ("[ox-fabrics: Accepting connections -> %s:%d\n", con->haddr.addr,
                                                               con->haddr.port);

    while (con->running) {

        //accept connection from an incoming client
        client_sock = raccept(con->sock_fd, (struct sockaddr *) &client, &len);

        if (client_sock < 0)
            continue;

        if (con->active_cli[pending_conn]) {
            log_info ("[ox-fabrics: Client %d is taking connection %d.]",
                                                    client_sock, pending_conn);
            con->active_cli[pending_conn] = 0;
            pthread_kill (con->cli_tid[pending_conn], 9);
        }

        con->active_cli[pending_conn] = client_sock + 1;

        if (pthread_create (&con->cli_tid[pending_conn], NULL,
                                        oxf_roce_server_con_th, (void *) arg)) {
            pending_conn = 0;
            log_err ("[ox-fabrics: Client thread not started: %d]",
                                                                 pending_conn);
        }

        while (pending_conn)
            usleep (1000);
    }

    return NULL;
}

static int oxf_roce_server_reply(struct oxf_server_con *con, const void *buf,
                                                 uint32_t size, void *recv_cli)
{
    int *client = (int *) recv_cli;
    int ret;

    if(con == NULL){
	printf("Foo");
    }

    ret = riowrite(*client - 1, buf, size, con->remote_offset, 0);
    if(ret != size){
        perror("RIO Write failed");
        return -1;
    }

    ret = rsend (*client - 1, &size, sizeof(size), 0);
    if (ret != sizeof(size)) {
        log_err ("[ox-fabrics: Completion reply hasn't been sent. %d]", ret);
        perror("RIO Notify failed");
        return -1;
    }

    return 0;
}

static int oxf_roce_server_con_start (struct oxf_server_con *con, oxf_rcv_fn *fn)
{
    if (con->running)
        return 0;

    con->running = 1;
    con->rcv_fn = fn;

    if (pthread_create (&con->tid, NULL, oxf_roce_server_accept_th, con)) {
	log_err ("[ox-fabrics: Connection not started.]");
	con->running = 0;
	return -1;
    }

    return 0;
}

static void oxf_roce_server_con_stop (struct oxf_server_con *con)
{
    uint32_t cli_id;

    if (con && con->running)
	con->running = 0;
    else
        return;

    for (cli_id = 0; cli_id < OXF_SERVER_MAX_CON; cli_id++) {
        if (con->active_cli[cli_id]) {
            con->active_cli[cli_id] = 0;
            pthread_kill (con->cli_tid[cli_id], 9);
        }
    }
    pthread_kill (con->tid, 9);
}

void oxf_roce_server_exit (struct oxf_server *server)
{
    uint32_t con_i;

    for (con_i = 0; con_i < OXF_SERVER_MAX_CON; con_i++)
        oxf_roce_server_con_stop (server->connections[con_i]);

    ox_free (server, OX_MEM_TCP_SERVER);
}

struct oxf_server_ops oxf_roce_srv_ops = {
    .bind    = oxf_roce_server_bind,
    .unbind  = oxf_roce_server_unbind,
    .start   = oxf_roce_server_con_start,
    .stop    = oxf_roce_server_con_stop,
    .reply   = oxf_roce_server_reply
};

struct oxf_server *oxf_roce_server_init (void)
{
    struct oxf_server *server;

    if (!ox_mem_create_type ("RoCE_SERVER", OX_MEM_TCP_SERVER))
        return NULL;

    server = ox_calloc (1, sizeof (struct oxf_server), OX_MEM_TCP_SERVER);
    if (!server)
	return NULL;

    server->ops = &oxf_roce_srv_ops;
    pending_conn = 0;

    log_info ("[ox-fabrics: Protocol -> RoCE\n");

    return server;
}
