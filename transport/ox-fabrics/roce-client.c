/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over RoCE (client side)
 *
 * Copyright 2020 IT University of Copenhagen
 *
 * Written by Niclas Hedam <nhed@itu.dk>
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
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <netdb.h>
#include <rdma/rdma_cma.h>
#include <rdma/rdma_verbs.h>
#include <ox-fabrics.h>
#include <libox.h>

static void *oxf_roce_client_recv (void *arg)
{
    int n;
    unsigned int len;
    uint8_t buf[OXF_MAX_DGRAM + 1];
    struct oxf_client_con *con = (struct oxf_client_con *) arg;

    len = sizeof (struct sockaddr);
    while (con->running) {
        n = recvfrom(con->sock_fd, (char *) buf, OXF_MAX_DGRAM,
                            MSG_WAITALL, ( struct sockaddr *) &con->addr, &len);
        if (n > 0)
            con->recv_fn (n, (void *) buf);
    }

    return NULL;
}

static struct oxf_client_con *oxf_roce_client_connect (struct oxf_client *client,
       uint16_t cid, const char *addr, uint16_t port, oxf_rcv_reply_fn *recv_fn)
{
    struct oxf_client_con *con = NULL;
    int ret;
    struct rdma_addrinfo hints, *res = NULL;
    struct ibv_qp_init_attr attr;
    struct rdma_cm_id *id = NULL;
    uint8_t connect[2], ack[2];

    if (cid >= OXF_SERVER_MAX_CON) {
        printf ("[ox-fabrics: Invalid connection ID: %d]", cid);
        return NULL;
    }

    if (client->connections[cid]) {
        printf ("[ox-fabrics: Connection already established: %d]", cid);
        return NULL;
    }

    con = calloc (1, sizeof (struct oxf_client_con));
    if (!con)
	return NULL;

    // Here the port would have been increased

    con->cid = cid;
    con->client = client;
    con->recv_fn = recv_fn;

    char cport[16];
    snprintf(cport, sizeof(cport), "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_port_space = RDMA_PS_UDP;

    connect[0] = OXF_CON_BYTE;

	memset(&attr, 0, sizeof attr);
    attr.cap.max_send_wr = attr.cap.max_recv_wr = 1;
	attr.cap.max_send_sge = attr.cap.max_recv_sge = 1;
	attr.sq_sig_all = 1;

    ret = rdma_getaddrinfo(addr, cport, &hints, &res);
    if (ret) {
        log_err ("[ox-fabrics: Socket creation failure. %d. %s]", con->sock_fd, gai_strerror(ret));
        goto NOT_CONNECTED;
    }

    ret = rdma_create_ep(&id, res, NULL, &attr);
    if (ret) {
        log_err ("[ox-fabrics: RoCE create EP failure.]");
        goto NOT_CONNECTED;
    }

    struct ibv_wc wc;
    struct ibv_mr *mr_ack = rdma_reg_msgs(id, ack, 2);

    ret = rdma_connect(id, NULL);
    if (ret) {
        log_err ("[ox-fabrics: Could not connect. Is the server running?]");
        perror("Could not connect");
        goto NOT_CONNECTED;
    }

    ret = rdma_post_send(id, NULL, connect, 2, NULL, 0);
	if (ret) goto NOT_CONNECTED;

	while ((ret = rdma_get_send_comp(id, &wc)) == 0);

	if (ret < 0)
        goto NOT_CONNECTED;
	else
		ret = 0;

    if (ret) {
        log_err ("[ox-fabrics: Completion reply hasn't been sent. %d]", ret);
        goto NOT_CONNECTED;
    }

    ret = rdma_post_recv(id, NULL, ack, 2, mr_ack);

    if(ret){
        log_err ("[ox-fabrics: error in rdma_post_recv]");
        goto NOT_CONNECTED;
    }

    ret = rdma_accept(id, NULL);
    if (ret) {
        log_err ("[ox-fabrics: error in rdma_accept]");
        goto NOT_CONNECTED;
    }

    while ((ret = rdma_get_recv_comp(id, &wc)) == 0);

    if (ack[0] != OXF_ACK_BYTE) {
        printf ("[ox-fabrics: Server responded, but byte is incorrect: %x]\n",
                                                                        ack[0]);
        goto NOT_CONNECTED;
    }

    con->running = 1;
    if (pthread_create(&con->recv_th, NULL, oxf_roce_client_recv, (void *) con)){
        printf ("[ox-fabrics: Receive reply thread not started.]");
        goto NOT_CONNECTED;
    }

    client->connections[cid] = con;
    client->n_con++;

    return con;

NOT_CONNECTED:
    if(id) rdma_disconnect(id);
    if(id) rdma_destroy_ep(id);
    if(con && con->listen_id) rdma_destroy_ep(con->listen_id);
    free (con);
    return NULL;
}

static int oxf_roce_client_send (struct oxf_client_con *con, uint32_t size,
                                                                const void *buf)
{
    struct ibv_wc wc;
    struct rdma_cm_id *id = (struct rdma_cm_id *) &con->addr;
    struct ibv_mr *mr = rdma_reg_msgs(id, &buf, 16);

    int ret = rdma_post_send(id, NULL, &buf, 16, mr, 0);
	if (ret) goto SEND_ERROR;

	while ((ret = rdma_get_send_comp(id, &wc)) == 0);
	if (ret < 0)
		goto SEND_ERROR;
	else
		ret = 0;

SEND_ERROR:
    if (ret) {
        log_err ("[ox-fabrics: Completion reply hasn't been sent. %d]", ret);
        return -1;
    }

    return 0;
}

static void oxf_roce_client_disconnect (struct oxf_client_con *con)
{
    if (con) {
        con->running = 0;
        pthread_join (con->recv_th, NULL);
        if(con->listen_id) rdma_destroy_ep(con->listen_id);
        con->client->connections[con->cid] = NULL;
        con->client->n_con--;
        free (con);
    }
}

void oxf_roce_client_exit (struct oxf_client *client)
{
    free (client);
}

struct oxf_client_ops oxf_roce_cli_ops = {
    .connect    = oxf_roce_client_connect,
    .disconnect = oxf_roce_client_disconnect,
    .send       = oxf_roce_client_send
};

struct oxf_client *oxf_roce_client_init (void)
{
    struct oxf_client *client;

    client = calloc (1, sizeof (struct oxf_client));
    if (!client)
	return NULL;

    client->ops = &oxf_roce_cli_ops;

    return client;
}
