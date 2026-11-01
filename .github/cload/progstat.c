// Print name, id, verified and xlated instruction counts of one BPF program. bpftool does not
// print verified_insns.
#include <linux/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv)
{
  union bpf_attr a;
  struct bpf_prog_info i;
  int fd;

  if (argc != 2) return 2;
  memset(&a, 0, sizeof(a));
  a.prog_id = atoi(argv[1]);
  fd = syscall(SYS_bpf, BPF_PROG_GET_FD_BY_ID, &a, sizeof(a));
  if (fd < 0) { perror("prog fd"); return 1; }
  memset(&i, 0, sizeof(i));
  memset(&a, 0, sizeof(a));
  a.info.bpf_fd = fd;
  a.info.info_len = sizeof(i);
  a.info.info = (unsigned long)&i;
  if (syscall(SYS_bpf, BPF_OBJ_GET_INFO_BY_FD, &a, sizeof(a))) { perror("prog info"); return 1; }
  printf("%s %u %u %u\n", i.name, i.id, i.verified_insns, i.xlated_prog_len / 8);
  return 0;
}
