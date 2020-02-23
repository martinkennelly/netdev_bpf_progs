/* SPDX-License-Identifier: GPL-2.0 */
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <linux/if_xdp.h>
#include <linux/if_link.h>
#include <net/if.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>


#define EXIT_GOOD 0
#define EXIT_FAIL 1
#define MAX_IFNAME_LEN 1000
#define MAX_PROG_NAME 1000
#define MAX_ATTACH_MODE_NAME 50

/* Author: Martin Kennelly - dalykennelly at gmail dot com */

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
  const char *usage = "Find eBPF program ID and attached mode for a "
                      "given interface\n\n"
                      "Usage:\nHelp: -h\nInterface: -i\n\n"
                      "Select an interface to scan for eBPF program ID and "
                      "its attached mode\n";

  if (unwrap_options(options, &long_options)) {
    fprintf(stderr, "Failed to allocate memory\n");
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
          fprintf(stderr, "Interface name is too long\n");
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

int main(int argc, char **argv)
{
  struct config cfg = {
    .ifindex = -1,
    .ifname_buff = "",
  };

  parse_args(argc, argv, long_options, &cfg);

  if (cfg.ifindex == -1) {
    fprintf(stderr, "Error: Failed to find interface. Please define '-i' arg "
                    "with a valid interface name\n\n");
    return EXIT_FAIL;
  }

  if (find_int_prog(cfg.ifindex, &cfg)) {
    fprintf(stdout, "Failed to find program ID on this interface\n");
    return EXIT_GOOD;
  }

  if (!cfg.link_info.prog_id) {
    printf("No XDP program attached to interface '%s'\n", cfg.ifname);
    return EXIT_GOOD;
  }

  if (convert_attach_mode_str(&cfg)) {
    fprintf(stderr, "Failed to convert attached mode to string");
      return EXIT_FAIL;
  }

  printf("Program ID:     %u\n", cfg.link_info.prog_id);
  printf("Attached mode:  %s\n", cfg.attach_mode_buff);

  return EXIT_GOOD;
}
