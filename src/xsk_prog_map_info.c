/* SPDX-License-Identifier: GPL-2.0 */
/* Author: Martin Kennelly - dalykennelly at gmail dot com */
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define EXIT_GOOD 0
#define EXIT_FAIL 1
#define MAX_IFNAME_LEN 1000
#define MAX_PROG_NAME 1000
#define MAX_ATTACH_MODE_NAME 50

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

// Based on kernel 5.4.0
const char * const bpf_map_type_name[] = {
	[BPF_MAP_TYPE_UNSPEC] 			= "Unspec",
	[BPF_MAP_TYPE_HASH] 			= "Hash",
	[BPF_MAP_TYPE_ARRAY] 			= "Array",
	[BPF_MAP_TYPE_PROG_ARRAY] 		= "Prog array",
	[BPF_MAP_TYPE_PERF_EVENT_ARRAY] 	= "Perf event array",
	[BPF_MAP_TYPE_PERCPU_HASH] 		= "Per CPU hash",
	[BPF_MAP_TYPE_PERCPU_ARRAY] 		= "Per CPU array",
	[BPF_MAP_TYPE_STACK_TRACE] 		= "Stack trace",
	[BPF_MAP_TYPE_CGROUP_ARRAY] 		= "Cgroup array",
	[BPF_MAP_TYPE_LRU_HASH] 		= "LRU hash",
	[BPF_MAP_TYPE_LRU_PERCPU_HASH] 		= "Per CPU hash",
	[BPF_MAP_TYPE_LPM_TRIE] 		= "LPM trie",
	[BPF_MAP_TYPE_ARRAY_OF_MAPS] 		= "Array of maps",
	[BPF_MAP_TYPE_HASH_OF_MAPS] 		= "Hash of maps",
	[BPF_MAP_TYPE_DEVMAP] 			= "Devmap",
	[BPF_MAP_TYPE_SOCKMAP] 			= "Socket map",
	[BPF_MAP_TYPE_CPUMAP] 			= "CPU map",
	[BPF_MAP_TYPE_XSKMAP] 			= "XSK map",
	[BPF_MAP_TYPE_SOCKHASH] 		= "Socket hash",
	[BPF_MAP_TYPE_CGROUP_STORAGE] 		= "Cgroup storage",
	[BPF_MAP_TYPE_REUSEPORT_SOCKARRAY] 	= "Reuseport socket array",
};

struct option_wrapper {
  struct option option;
  char *help;
  bool required;
};

struct config {
  int ifindex;
  char *ifname;
  char ifname_buff[MAX_IFNAME_LEN];
  struct xdp_link_info link_info;
  char attach_mode_buff[MAX_ATTACH_MODE_NAME];
};

static const struct option_wrapper long_options[] = {
  {{"help",      no_argument,       NULL, 'h'},
    "Display help", false},
  {{"interface", required_argument, NULL, 'i'},
    "Search on interface for bpf progs", true},
  {{0, 0, NULL, 0},                 NULL, false}
};

int unwrap_options(const struct option_wrapper *wrapper,
                   struct option **options)
{
  int i, total_opts;
  struct option *new_options;

  for (i = 0; wrapper[i].option.name != 0; i++) {};
  total_opts = i;

  new_options = malloc(total_opts * sizeof(struct option));
  if (!new_options)
    return -1;

  for (i = 0; i < total_opts; i++)
    memcpy(&new_options[i], &wrapper[i], sizeof(struct option));

  *options = new_options;
  return 0;
}

void parse_args(int argc, char **argv, const struct option_wrapper *options,
                struct config *cfg)
{
  struct option *long_options;
  int longindex = 0;
  int opt;
  const char *usage = "Find BPF program and map information for a "
                      "given netdev\n\n"
                      "Usage:\nSpecify netdevice name after flag 'i'\n"
                      "e.g './xsk_prog_map_info -i eno1'\n\n";

  if (unwrap_options(options, &long_options)) {
    fprintf(stderr, "Error: Failed to allocate memory\n");
    exit(EXIT_FAIL);
  }

  while (( opt = getopt_long(argc, argv, "hi:", long_options, &longindex)) != -1) {
    switch(opt) {
      /* help option */
      case 'h':
        fprintf(stdout, usage);
        free(long_options);
        exit(EXIT_GOOD);
      /* interface option */
      case 'i':
        if (strlen(optarg) > MAX_IFNAME_LEN) {
          fprintf(stderr, "Error: Interface name is too long\n");
          goto error;
        }

        cfg->ifname = (char *)&cfg->ifname_buff;
        snprintf(cfg->ifname, MAX_IFNAME_LEN, "%s", optarg);

        cfg->ifindex = if_nametoindex(cfg->ifname);
        if (cfg->ifindex == 0) {
          fprintf(stderr, "Error: Could not find interface '%s'\n", cfg->ifname);
          goto error;
        }
        break;
      error:
      default:
        fprintf(stderr, usage);
        free(long_options);
        exit(EXIT_FAIL);
    }
  }
  free(long_options);
}

int find_int_prog(int ifindex, struct config *cfg)
{
  size_t info_size  = sizeof(struct xdp_link_info);
  __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

  if (bpf_get_link_xdp_info(ifindex, &cfg->link_info, info_size, xdp_flags))
    return -1;

  return 0;
}

int convert_attach_mode_str(struct config *cfg) {
  int ret = 0;

  switch(cfg->link_info.attach_mode) {
   case XDP_ATTACHED_NONE:
     snprintf(cfg->attach_mode_buff, MAX_ATTACH_MODE_NAME,
              "%s", "XDP_ATTACHED_NONE - Program not attached");
     break;
   case XDP_ATTACHED_DRV:
     snprintf(cfg->attach_mode_buff, MAX_ATTACH_MODE_NAME,
              "%s", "XDP_ATTACHED_DRV - Attached with driver support");
     break;
   case XDP_ATTACHED_SKB:
     snprintf(cfg->attach_mode_buff, MAX_ATTACH_MODE_NAME,
              "%s", "XDP_ATTACHED_SKB - In SKB mode");
     break;
   case XDP_ATTACHED_HW:
     snprintf(cfg->attach_mode_buff, MAX_ATTACH_MODE_NAME,
              "%s", "XDP_ATTACHED_HW - Offloaded to HW");
     break;
   default:
     snprintf(cfg->attach_mode_buff, MAX_ATTACH_MODE_NAME,
              "%s", "(Invalid attach mode)");
     ret = -1;
  }
  return ret;
}

void print_map_details(__u32 prog_id)
{
  __u32 *map_ids, num_maps;
  __u32 prog_len = sizeof(struct bpf_prog_info);
  __u32 map_len = sizeof(struct bpf_map_info);
  struct bpf_prog_info prog_info = {};
  struct bpf_map_info map_info;
  int err, prog_fd, map_fd;

  prog_fd = bpf_prog_get_fd_by_id(prog_id);

  if (prog_fd < 0) {
    fprintf(stderr, "Error: Failed to get fd of BPF program\n");
    exit(EXIT_FAIL);
  }

  err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);

  if(err) {
    fprintf(stderr, "Error: Failed to get information about BPF program\n");
    close(prog_fd);
    exit(EXIT_FAIL);
  }

  num_maps = prog_info.nr_map_ids;
  map_ids = calloc(num_maps, sizeof(*map_ids));

  if (!map_ids) {
    fprintf(stderr, "Error: Failed to allocate memory\n");
    close(prog_fd);
    exit(EXIT_FAIL);
  }

  memset(&prog_info, 0, prog_len);
  prog_info.nr_map_ids = num_maps;
  prog_info.map_ids = (__u64)(unsigned long)map_ids;

  err = bpf_obj_get_info_by_fd(prog_fd, &prog_info, &prog_len);
  close(prog_fd);

  if (err) {
    fprintf(stderr, "Error: Failed to get BPF program information\n");
    free(map_ids);
    exit(EXIT_FAIL);
  }

  if (num_maps)
    printf("# netdev map information\n");

  for (int i = 0; i < num_maps; i++) {
    printf("map %d of %d\n", i+1, num_maps);
    map_fd = bpf_map_get_fd_by_id(map_ids[i]);
    if (map_fd < 0) {
      fprintf(stderr, "Error: Failed to get map fd with map id '%u'", map_ids[i]);
      continue;
    }

    err = bpf_obj_get_info_by_fd(map_fd, &map_info, &map_len);
    if (err) {
      fprintf(stderr, "Error: Failed to get map information\n");
      close(map_fd);
      continue;
    }

    printf("\tid: %u\n", map_ids[i]);
    printf("\tname: %s\n", map_info.name);

    if (map_info.type < ARRAY_SIZE(bpf_map_type_name))
      printf("\ttype: %s\n", bpf_map_type_name[map_info.type]);
    else
      printf("\ttype: %u\n", map_info.type);

    printf("\tflags: 0x%x\n", map_info.map_flags);

    close(map_fd);
   }
  free(map_ids);
}

void print_prog_details(struct config *cfg) {
  if (find_int_prog(cfg->ifindex, cfg)) {
    fprintf(stdout, "Failed to find program ID on this interface\n");
    exit(EXIT_GOOD);
  }

  if (!cfg->link_info.prog_id) {
    printf("No XDP program attached to interface '%s'\n", cfg->ifname);
    exit(EXIT_GOOD);
  }

  if (convert_attach_mode_str(cfg)) {
    fprintf(stderr, "Error: Failed to convert attached mode to string\n");
      exit(EXIT_FAIL);
  }

  printf("# netdev BPF program information\n");
  printf("\tid: %u\n", cfg->link_info.prog_id);
  printf("\tattached mode: %s\n", cfg->attach_mode_buff);
}

int main(int argc, char **argv)
{
  struct config cfg = {
    .ifindex = -1,
    .ifname_buff = "",
  };

  if (getuid()) {
    fprintf(stderr, "Error: Run this application as root user\n");
    return EXIT_FAIL;
  }

  parse_args(argc, argv, long_options, &cfg);

  if (cfg.ifindex == -1) {
    fprintf(stderr, "Error: Failed to find interface. Please define '-i' arg "
                    "with a valid interface name\n\n");
    return EXIT_FAIL;
  }

  print_prog_details(&cfg);
  print_map_details(cfg.link_info.prog_id);

  return EXIT_GOOD;
}
