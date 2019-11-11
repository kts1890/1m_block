#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>  /* for NF_ACCEPT */
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <string.h>
#include <libnet.h>
#include <string.h>
#include <unordered_set>
#include <iostream>

using namespace std;
bool is_exist(unordered_set<string>&s, string str) {
 auto itr = s.find(str);
 if (itr != s.end())
  return true;
 else
  return false;
}
unordered_set<string> m;

char bad_site[100] = { "Host: " };

int cp(unsigned char* arr, int num) {
 int ret = 0;
 for (int i = 0;i<strlen(bad_site);i++) {
  if (arr[i + num] == bad_site[i])
   ret += 1;
 }
 if (ret == strlen(bad_site))
  return 0;
 else
  return 1;
}
/* returns packet id */

static u_int32_t print_pkt(struct nfq_data *tb, struct nfq_q_handle *qh)
{
 int id = 0;
 struct nfqnl_msg_packet_hdr *ph;
 struct nfqnl_msg_packet_hw *hwph;
 u_int32_t mark, ifi;
 int ret;
 unsigned char *data;


 ph = nfq_get_msg_packet_hdr(tb);
 if (ph) {
  id = ntohl(ph->packet_id);
  printf("hw_protocol=0x%04x hook=%u id=%u ",
   ntohs(ph->hw_protocol), ph->hook, id);
 }


 hwph = nfq_get_packet_hw(tb);
 if (hwph) {
  int i, hlen = ntohs(hwph->hw_addrlen);


  printf("hw_src_addr=");
  for (i = 0; i < hlen - 1; i++)
   printf("%02x:", hwph->hw_addr[i]);
  printf("%02x ", hwph->hw_addr[hlen - 1]);
 }


 mark = nfq_get_nfmark(tb);
 if (mark)
  printf("mark=%u ", mark);


 ifi = nfq_get_indev(tb);

 if (ifi)
  printf("indev=%u ", ifi);


 ifi = nfq_get_outdev(tb);
 if (ifi)
  printf("outdev=%u ", ifi);
 ifi = nfq_get_physindev(tb);
 if (ifi)
  printf("physindev=%u ", ifi);


 ifi = nfq_get_physoutdev(tb);
 if (ifi)
  printf("physoutdev=%u ", ifi);

 ret = nfq_get_payload(tb, &data);
 if (ret >= 0)
  printf("payload_len=%d ", ret);

 fputc('\n', stdout);

 u_int32_t  filter = 0;
 int block = 0;
 for (int i = 0;i<ret - strlen(bad_site);i++) {
  if (!cp(data, i))
  {
   int t = 0;
   char arr[100];
   while (data[i + t+6] != '.') {
    arr[t] = data[i + t + 6];
    t++;
   }
   arr[t + 1] = 0;
   if (is_exist(m, arr))
    block = 1;
   break;
  }
 }
 if (block != 0) {
  filter = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
  printf("This is bad site!\n");
 }
 else
  filter = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
 return filter;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
 struct nfq_data *nfa, void *data)

{
 u_int32_t id = print_pkt(nfa, qh);
 return id;
}

int main(int argc, char **argv)
{
 if (argc != 2) {
  printf("syntax : 1m_block <host>\n");
  return -1;
 }
 FILE *fp;
 char filename[100] = "./";
 strcat(filename, argv[1]);
 fp = fopen(filename, "r");
 if (fp == NULL) {
  printf("file open error\n");
  return -1;
 }
 char str[100];
 size_t len = 0;
 while (!feof(fp)) {
  fscanf(fp, "%s\n", str);
  char *tok = strtok(str, ",");
  tok = strtok(NULL, ",");
  string st(tok);
  m.insert(st);
 }
 struct nfq_handle *h;
 struct nfq_q_handle *qh;
 struct nfnl_handle *nh;
 int fd;
 int rv;
 char buf[4096] __attribute__((aligned));
 printf("opening library handle\n");
 h = nfq_open();
 if (!h) {
  fprintf(stderr, "error during nfq_open()\n");
  exit(1);
 }

 printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
 if (nfq_unbind_pf(h, AF_INET) < 0) {
  fprintf(stderr, "error during nfq_unbind_pf()\n");
  exit(1);
 }
 printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
 if (nfq_bind_pf(h, AF_INET) < 0) {
  fprintf(stderr, "error during nfq_bind_pf()\n");
  exit(1);
 }
 printf("binding this socket to queue '0'\n");
 qh = nfq_create_queue(h, 0, &cb, NULL);
 if (!qh) {
  fprintf(stderr, "error during nfq_create_queue()\n");
  exit(1);
 }
 printf("setting copy_packet mode\n");
 if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
  fprintf(stderr, "can't set packet_copy mode\n");
  exit(1);
 }
 fd = nfq_fd(h);
 for (;;) {
  if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
   printf("pkt received\n");
   nfq_handle_packet(h, buf, rv);
   continue;
  }
  if (rv < 0 && errno == ENOBUFS) {
   printf("losing packets!\n");
   continue;
  }
  perror("recv failed");
  break;
 }
 printf("unbinding from queue 0\n");
 nfq_destroy_queue(qh);
#ifdef INSANE
 /* normally, applications SHOULD NOT issue this command, since
 * it detaches other programs/sockets from AF_INET, too ! */
 printf("unbinding from AF_INET\n");
 nfq_unbind_pf(h, AF_INET);
#endif
 printf("closing library handle\n");
 nfq_close(h);
 exit(0);
}
 

