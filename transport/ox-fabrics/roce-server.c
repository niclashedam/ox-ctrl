/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over roce (server side)
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
#include <sched.h>
#include <errno.h>
#include <ox-fabrics.h>
#include <libox.h>

#include <rdma/rsocket.h>

static struct oxf_server_con *oxf_roce_server_bind (struct oxf_server *server,
                                uint16_t cid, const char *addr, uint16_t port)
{
  return oxf_tcp_srv_ops.bind(server, cid, addr, port);
}

static void oxf_roce_server_unbind (struct oxf_server_con *con)
{
  oxf_tcp_srv_ops.unbind(con);
}


static int oxf_roce_server_con_start (struct oxf_server_con *con, oxf_rcv_fn *fn)
{
  return oxf_tcp_srv_ops.start(con, fn);
}

static void oxf_roce_server_con_stop (struct oxf_server_con *con)
{
  oxf_tcp_srv_ops.stop(con);
}

static int oxf_roce_server_reply (struct oxf_server_con *con, const void *buf,
                                                 uint32_t size, void *recv_cli)
{
  return oxf_tcp_srv_ops.reply(con, buf, size, recv_cli);
}

off_t oxf_roce_server_map (struct oxf_server *server, uint16_t cid, void *buffer, uint32_t size){
    struct oxf_server_con *con = server->connections[cid];
    return riomap(con->sock_fd, buffer, size, PROT_WRITE, 0, -1);
}

int oxf_roce_server_unmap (struct oxf_server *server, uint16_t cid, void *buffer, uint32_t size){
    struct oxf_server_con *con = server->connections[cid];
    return riounmap(con->sock_fd, buffer, size);
}

struct oxf_server_ops oxf_roce_srv_ops = {
    .bind    = oxf_roce_server_bind,
    .unbind  = oxf_roce_server_unbind,
    .start   = oxf_roce_server_con_start,
    .stop    = oxf_roce_server_con_stop,
    .reply   = oxf_roce_server_reply,

    .map     = oxf_roce_server_map,
    .unmap   = oxf_roce_server_unmap
};

struct oxf_server *oxf_roce_server_init (void)
{
  return oxf_tcp_server_init();
}

void oxf_roce_server_exit (struct oxf_server *server)
{
  return oxf_tcp_server_exit(server);
}
