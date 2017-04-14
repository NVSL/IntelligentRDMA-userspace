#define _GNU_SOURCE  // enables asprintf()
#include <stdio.h>
#include <unistd.h>  // sysconf()
#include <stdlib.h>  // aligned_alloc()
#include <string.h>  // memset()
#include <stdbool.h>
#include <infiniband/verbs.h>
#include <sys/socket.h>
#include <netdb.h>  // struct addrinfo
#include <arpa/inet.h>  // inet_ntop

#include "pingpong.h"  // wire_gid_to_gid, etc

#define ERROR(...) { printf(__VA_ARGS__); exit(1); }

#define BUF_SIZE_BYTES 4096
#define RX_DEPTH 500
#define GIDX 1
#define SERVER_IP ("192.168.1.11")
#define PORT 18515
#define IB_PORT 1

static void prepare_qp_for_send_recv(
    struct ibv_qp* qp,
    int my_psn,
    int rem_lid,
    int rem_qpn,
    int rem_psn,
    enum ibv_mtu mtu,
    union ibv_gid* rem_ibv_gid
) {
  struct ibv_qp_attr attr = {
    .qp_state = IBV_QPS_RTR,
    .path_mtu = mtu,
    .dest_qp_num = rem_qpn,
    .rq_psn = rem_psn,
    .max_dest_rd_atomic = 1,
    .min_rnr_timer = 12,
    .ah_attr = {
      .is_global = 0,
      .dlid = rem_lid,
      .sl = 0,
      .src_path_bits = 0,
      .port_num = IB_PORT
    }
  };
  if(rem_ibv_gid->global.interface_id) {
    attr.ah_attr.is_global = 1;
    attr.ah_attr.grh.hop_limit = 1;
    attr.ah_attr.grh.dgid = *rem_ibv_gid;
    attr.ah_attr.grh.sgid_index = GIDX;
  }
  if(ibv_modify_qp(qp, &attr,
        IBV_QP_STATE |
        IBV_QP_AV |
        IBV_QP_PATH_MTU |
        IBV_QP_DEST_QPN |
        IBV_QP_RQ_PSN |
        IBV_QP_MAX_DEST_RD_ATOMIC |
        IBV_QP_MIN_RNR_TIMER
    )) ERROR("Failed to modify QP to RTR\n")

  attr.qp_state = IBV_QPS_RTS;
  attr.timeout = 14;
  attr.retry_cnt = 7;
  attr.rnr_retry = 7;
  attr.sq_psn = my_psn;
  attr.max_rd_atomic = 1;
  if(ibv_modify_qp(qp, &attr,
        IBV_QP_STATE |
        IBV_QP_TIMEOUT |
        IBV_QP_RETRY_CNT |
        IBV_QP_RNR_RETRY |
        IBV_QP_SQ_PSN |
        IBV_QP_MAX_QP_RD_ATOMIC
    )) ERROR("Failed to modify QP to RTS\n")
}

static void initializeConnection(
    struct ibv_context* context,
    struct ibv_qp* qp,
    bool server
) {
  struct ibv_port_attr port_attr;
  struct addrinfo *res, *t;
  struct addrinfo hints = {
    .ai_family = AF_UNSPEC,
    .ai_socktype = SOCK_STREAM
  };
  if(server) hints.ai_flags = AI_PASSIVE;
  char* service;
  char msg[sizeof "0000:000000:000000:00000000000000000000000000000000"];
  char my_wgid[33], rem_wgid[33];
  int n;
  int sockfd = -1, connfd;
  enum ibv_mtu mtu = IBV_MTU_1024;
  int my_lid, my_qpn, my_psn;
  int rem_lid, rem_qpn, rem_psn;
  union ibv_gid my_ibv_gid, rem_ibv_gid;

  if(ibv_query_port(context, IB_PORT, &port_attr)) ERROR("Failed to get port info\n")
  my_lid = port_attr.lid;
  if(port_attr.link_layer != IBV_LINK_LAYER_ETHERNET && !my_lid) ERROR("Failed to get local LID\n")
  if(ibv_query_gid(context, IB_PORT, GIDX, &my_ibv_gid)) ERROR("Failed to read sgid of index %d\n", GIDX)
  my_qpn = qp->qp_num;
  srand48(getpid() * time(NULL));
  my_psn = lrand48() & 0xffffff;
  inet_ntop(AF_INET6, &my_ibv_gid, my_wgid, sizeof(my_wgid));
  printf("  local address:  LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
      my_lid, my_qpn, my_psn, my_wgid);
  if(asprintf(&service, "%d", PORT) < 0) ERROR("Failed asprintf\n")
  n = getaddrinfo(server ? NULL : SERVER_IP, service, &hints, &res);
  if(n < 0) ERROR("%s for port %d\n", gai_strerror(n), PORT)
  for(t = res; t; t = t->ai_next) {
    sockfd = socket(t->ai_family, t->ai_socktype, t->ai_protocol);
    if(sockfd >= 0) {
      if(server) {
        n = 1;
        setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &n, sizeof(n));
        if(!bind(sockfd, t->ai_addr, t->ai_addrlen)) break;
      } else {
        if(!connect(sockfd, t->ai_addr, t->ai_addrlen)) break;
      }
      close(sockfd);
      sockfd = -1;
    }
  }
  freeaddrinfo(res);
  free(service);
  if(sockfd < 0) {
    if(server) ERROR("Failed to listen to port %d\n", PORT)
    else ERROR("Failed to connect to %s:%d\n", SERVER_IP, PORT)
  }
  if(server) {
    listen(sockfd, 1);
    connfd = accept(sockfd, NULL, NULL);
    close(sockfd);
    if(connfd < 0) ERROR("Failed to accept()\n")
    n = read(connfd, msg, sizeof(msg));
    if(n != sizeof(msg)) ERROR("%d/%d: Server failed to read remote address\n", n, (int)sizeof(msg))
    sscanf(msg, "%x:%x:%x:%s", &rem_lid, &rem_qpn, &rem_psn, rem_wgid);
    wire_gid_to_gid(rem_wgid, &rem_ibv_gid);
    prepare_qp_for_send_recv(qp, my_psn, rem_lid, rem_qpn, rem_psn, mtu, &rem_ibv_gid);
  }
  gid_to_wire_gid(&my_ibv_gid, my_wgid);
  sprintf(msg, "%04x:%06x:%06x:%s", my_lid, my_qpn, my_psn, my_wgid);
  if(server) {
    if(write(connfd, msg, sizeof(msg)) != sizeof(msg) ||
        read(connfd, msg, sizeof(msg)) != sizeof("done")) ERROR("Server failed to send/recv local address\n")
  } else {
    if(write(sockfd, msg, sizeof(msg)) != sizeof(msg)) ERROR("Client failed to send local address\n")
    if(read(sockfd, msg, sizeof(msg)) != sizeof(msg) ||
        write(sockfd, "done", sizeof("done")) != sizeof("done")) ERROR("Client failed to read/write remote address\n")
    sscanf(msg, "%x:%x:%x:%s", &rem_lid, &rem_qpn, &rem_psn, rem_wgid);
    wire_gid_to_gid(rem_wgid, &rem_ibv_gid);
  }
  inet_ntop(AF_INET6, &rem_ibv_gid, rem_wgid, sizeof(rem_wgid));
  printf("  remote address: LID 0x%04x, QPN 0x%06x, PSN 0x%06x, GID %s\n",
      rem_lid, rem_qpn, rem_psn, rem_wgid);
  if(!server) prepare_qp_for_send_recv(qp, my_psn, rem_lid, rem_qpn, rem_psn, mtu, &rem_ibv_gid);
}

// If one of the (recv) completions contains an immediate value, that value will be returned
// If more than one of the (recv) completions do, one value will be chosen in an unspecified manner
// If none do, the value 0 will be returned
uint32_t waitForCompletions(unsigned howMany, struct ibv_cq* cq) {
  int ne, i;
  struct ibv_wc wc[howMany];
  unsigned completions = 0;
  uint32_t retval = 0;
  while(completions < howMany) {
    do {
      ne = ibv_poll_cq(cq, 2, wc);
      if(ne < 0) ERROR("Failed to poll CQ\n")
    } while (ne < 1);
    for(i = 0; i < ne; ++i) {
      enum ibv_wc_status status = wc[i].status;
      int wr_id = (int)wc[i].wr_id;
      if(status != IBV_WC_SUCCESS) ERROR("Failed status %s (%d) for wr_id %d\n",
          ibv_wc_status_str(status), status, wr_id)
      completions++;
      if((wc[i].opcode & IBV_WC_RECV) && (wc[i].wc_flags & IBV_WC_WITH_IMM)) {
        retval = wc[i].imm_data;
      }
    }
  }
  return retval;
}

struct remote_addr_info {
  uint64_t remote_addr;
  uint32_t rkey;
};

int main(int argc, char* argv[]) {
  struct ibv_device** dev_list;
  struct ibv_device* ibv_dev;
  struct ibv_context* context;
  struct ibv_pd* pd;
  struct ibv_mr* mr;
  struct ibv_cq* cq;
  struct ibv_qp* qp;
  int send_flags = IBV_SEND_SIGNALED;

  char temp;
  bool server;
  struct ibv_mr *local_mr, *rem_mr;
  struct remote_addr_info remote_addr_info, local_addr_info;

  int page_size = sysconf(_SC_PAGESIZE);
  int* buf = (int*)aligned_alloc(page_size, BUF_SIZE_BYTES);
  if(!buf) ERROR("Failed to allocate buf")

  if(argc != 2) ERROR("Wrong number of arguments\n")
  if(!sscanf(argv[1], "%c", &temp)) ERROR("Invalid argument\n")
  if(temp == 'c') server = false;
  else if(temp == 's') server = true;
  else ERROR("Bad argument value %c, expecting 'c' or 's'\n", temp)

  dev_list = ibv_get_device_list(NULL);
  if(!dev_list) ERROR("Failed to get device list\n")
  ibv_dev = *dev_list;
  if(!ibv_dev) ERROR("No devices in list\n")
  printf("Found (and using) IB device %s\n", ibv_get_device_name(ibv_dev));
  context = ibv_open_device(ibv_dev);
  if(!context) ERROR("Failed to get context for %s\n", ibv_get_device_name(ibv_dev))
  pd = ibv_alloc_pd(context);
  if(!pd) ERROR("Failed to allocate PD\n")
  mr = ibv_reg_mr(pd, buf, BUF_SIZE_BYTES, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
  if(!mr) ERROR("Failed to register MR\n")
  cq = ibv_create_cq(context, RX_DEPTH + 1, NULL, NULL, 0);
  if(!cq) ERROR("Failed to create CQ\n")

  // Create QP
  {
    struct ibv_qp_attr attr;
    struct ibv_qp_init_attr init_attr = {
      .send_cq = cq,
      .recv_cq = cq,
      .cap = {
        .max_send_wr = 1,
        .max_recv_wr = RX_DEPTH,
        .max_send_sge = 1,
        .max_recv_sge = 1
      },
      .qp_type = IBV_QPT_RC
    };
    qp = ibv_create_qp(pd, &init_attr);
    if(!qp) ERROR("Failed to create QP\n")
    ibv_query_qp(qp, &attr, IBV_QP_CAP, &init_attr);
    if(init_attr.cap.max_inline_data >= BUF_SIZE_BYTES) {
      send_flags |= IBV_SEND_INLINE;
    }
  }
  {
    struct ibv_qp_attr attr = {
      .qp_state = IBV_QPS_INIT,
      .pkey_index = 0,
      .port_num = IB_PORT,
      .qp_access_flags = 0
    };
    if(ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX | IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) ERROR("Failed to modify QP to INIT\n")
  }

  // initialize buffer
  {
    int i;
#define SERVER_DATA (0x51)
#define CLIENT_DATA (0x7a)
    for(i = 0; i < BUF_SIZE_BYTES/sizeof(int); i++) {
      buf[i] = server ? SERVER_DATA : CLIENT_DATA;
    }
  }

  // post receive
  {
    struct ibv_sge sge_list = {
      .addr = (uintptr_t)(&buf[4]),
      .length = 4*sizeof(int),
      .lkey = mr->lkey
    };
    struct ibv_recv_wr recv_wr = {
      .wr_id = 1,
      .sg_list = &sge_list,
      .num_sge = 1,
    };
    struct ibv_recv_wr* bad_recv_wr;
    if(ibv_post_recv(qp, &recv_wr, &bad_recv_wr)) ERROR("Failed to post receive\n")
  }

  // initialize connection
  initializeConnection(context, qp, server);

  // post send
  {
    struct ibv_sge sge_list = {
      .addr = (uintptr_t)buf,
      .length = 4*sizeof(int),
      .lkey = mr->lkey
    };
    struct ibv_send_wr send_wr = {
      .wr_id = 2,
      .sg_list = &sge_list,
      .num_sge = 1,
      .opcode = IBV_WR_SEND,
      .send_flags = send_flags,
    };
    struct ibv_send_wr* bad_send_wr;
    if(ibv_post_send(qp, &send_wr, &bad_send_wr)) ERROR("Failed to post send\n")
  }

  // wait for completions, and confirm correct data received
  {
    int i;
    waitForCompletions(2, cq);
    for(i = 4; i < 8; i++) {
      int expected_data = server ? CLIENT_DATA : SERVER_DATA;
      if(buf[i] != expected_data) ERROR("Received data 0x%x in position %i; expected 0x%x\n",
          buf[i], i, expected_data)
    }
  }

  // next round: inc everything in buffer
  {
    int i;
    for(i = 0; i < BUF_SIZE_BYTES/sizeof(int); i++) {
      buf[i]++;
    }
  }

  // post next receive
  {
    struct ibv_sge sge_list = {
      .addr = (uintptr_t)(&buf[4]),
      .length = 4*sizeof(int),
      .lkey = mr->lkey
    };
    struct ibv_recv_wr recv_wr = {
      .wr_id = 3,
      .sg_list = &sge_list,
      .num_sge = 1,
    };
    struct ibv_recv_wr* bad_recv_wr;
    if(ibv_post_recv(qp, &recv_wr, &bad_recv_wr)) ERROR("Failed to post receive\n")
  }

  // post send with immediate
#define IMM_DATA 5
  {
    struct ibv_sge sge_list = {
      .addr = (uintptr_t)buf,
      .length = 4*sizeof(int),
      .lkey = mr->lkey
    };
    struct ibv_send_wr send_wr = {
      .wr_id = 4,
      .sg_list = &sge_list,
      .num_sge = 1,
      .opcode = IBV_WR_SEND_WITH_IMM,
      .send_flags = send_flags,
      .imm_data = IMM_DATA,
    };
    struct ibv_send_wr* bad_send_wr;
    if(ibv_post_send(qp, &send_wr, &bad_send_wr)) ERROR("Failed to post send\n")
  }

  // wait for completions, and confirm correct data received
  {
    int i;
    uint32_t imm = waitForCompletions(2, cq);
    for(i = 4; i < 8; i++) {
      int expected_data = server ? CLIENT_DATA+1 : SERVER_DATA+1;
      if(buf[i] != expected_data) ERROR("Received data 0x%x in position %i; expected 0x%x\n",
          buf[i], i, expected_data)
    }
    if(imm != IMM_DATA) ERROR("Received imm_data %u, expected %u\n", imm, IMM_DATA)
  }

  // interlude: send address and rkey so the other side can conduct RDMA Write with it
  local_addr_info.remote_addr = (uintptr_t)buf;
  local_addr_info.rkey = mr->rkey;
  local_mr = ibv_reg_mr(pd, &local_addr_info, sizeof(struct remote_addr_info), 0);
  if(!local_mr) ERROR("Failed to register local MR\n")
  rem_mr = ibv_reg_mr(pd, &remote_addr_info, sizeof(struct remote_addr_info), IBV_ACCESS_LOCAL_WRITE);
  if(!rem_mr) ERROR("Failed to register remote MR\n")
  {
    struct ibv_sge sge_list = {
      .addr = (uintptr_t)(&remote_addr_info),
      .length = sizeof(struct remote_addr_info),
      .lkey = rem_mr->lkey
    };
    struct ibv_recv_wr recv_wr = {
      .wr_id = 5,
      .sg_list = &sge_list,
      .num_sge = 1,
    };
    struct ibv_recv_wr* bad_recv_wr;
    if(ibv_post_recv(qp, &recv_wr, &bad_recv_wr)) ERROR("Failed to post receive\n")
  }
  {
    struct ibv_sge sge_list = {
      .addr = (uintptr_t)(&local_addr_info),
      .length = sizeof(struct remote_addr_info),
      .lkey = local_mr->lkey
    };
    struct ibv_send_wr send_wr = {
      .wr_id = 6,
      .sg_list = &sge_list,
      .num_sge = 1,
      .opcode = IBV_WR_SEND,
      .send_flags = send_flags,
    };
    struct ibv_send_wr* bad_send_wr;
    if(ibv_post_send(qp, &send_wr, &bad_send_wr)) ERROR("Failed to post send\n")
  }
  waitForCompletions(2, cq);

  // next round: inc everything in buffer
  {
    int i;
    for(i = 0; i < BUF_SIZE_BYTES/sizeof(int); i++) {
      buf[i]++;
    }
  }

  // post next receive
  {
    struct ibv_recv_wr recv_wr = {
      .wr_id = 7,
    };
    struct ibv_recv_wr* bad_recv_wr;
    if(ibv_post_recv(qp, &recv_wr, &bad_recv_wr)) ERROR("Failed to post receive\n")
  }

  // post RDMA Write with immediate
  {
    struct ibv_sge sge_list = {
      .addr = (uintptr_t)buf,
      .length = 4*sizeof(int),
      .lkey = mr->lkey
    };
    struct ibv_send_wr send_wr = {
      .wr_id = 8,
      .sg_list = &sge_list,
      .num_sge = 1,
      .opcode = IBV_WR_RDMA_WRITE_WITH_IMM,
      .send_flags = send_flags,
      .imm_data = IMM_DATA,
      .wr.rdma = {
        .remote_addr = remote_addr_info.remote_addr + 8*sizeof(int),
        .rkey = remote_addr_info.rkey,
      }
    };
    struct ibv_send_wr* bad_send_wr;
    if(ibv_post_send(qp, &send_wr, &bad_send_wr)) ERROR("Failed to post send\n")
  }

  // wait for completions, and confirm correct data received
  {
    int i;
    uint32_t imm = waitForCompletions(2, cq);
    for(i = 8; i < 12; i++) {
      int expected_data = server ? CLIENT_DATA+2 : SERVER_DATA+2;
      if(buf[i] != expected_data) ERROR("Received data 0x%x in position %i; expected 0x%x\n",
          buf[i], i, expected_data)
    }
    if(imm != IMM_DATA) ERROR("Received imm_data %u, expected %u\n", imm, IMM_DATA)
  }

  printf("All tests successful.\n");
  return 0;
}

