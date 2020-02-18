/* OX: Open-Channel NVM Express SSD Controller
 *
 *  - OX NVMe over TCP
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

#include <ox-fabrics.h>

#ifndef OX_FABRICS_TCP_H
#define OX_FABRICS_TCP_H

// Client
struct oxf_client_con *oxf_tcp_client_connect (struct oxf_client *client,
       uint16_t cid, const char *addr, uint16_t port, oxf_rcv_reply_fn *recv_fn);
void oxf_tcp_client_disconnect (struct oxf_client_con *con);
int oxf_tcp_client_send (struct oxf_client_con *con, uint32_t size,
                                                                const void *buf);

// Server
struct oxf_server_con *oxf_tcp_server_bind (struct oxf_server *server,
                                uint16_t cid, const char *addr, uint16_t port);
void oxf_tcp_server_unbind (struct oxf_server_con *con);
int oxf_tcp_server_con_start (struct oxf_server_con *con, oxf_rcv_fn *fn);
void oxf_tcp_server_con_stop (struct oxf_server_con *con);
int oxf_tcp_server_reply(struct oxf_server_con *con, const void *buf,
                                                 uint32_t size, void *recv_cli);

#endif /* OX_FABRICS_TCP_H */
