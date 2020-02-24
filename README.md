# netdev_bpf_progs
Output a user defined netdev's BPF program ID and the program's attached mode

## Usage
./xsk_prog_mode -i ${interface_name}

## Sample execution
```bash
./xsk_prog_mode -i eno1
Program ID:     17
Attached mode:  XDP_ATTACHED_DRV - Attached with driver support
```

## Testing
Tested on Debian 10 Linux kernel 5.4.3

Tested with libbpf ver. 0.0.7

Compiled with GCC 8.3.0

## Prerequirements
Compile and install libbpf

Linux kernel > 4.19

## Compilation
```bash
export LD_LIBRARY_PATH=${path_of_libbpf}
gcc -o xsk_prog_mode xsk_prog_mode.c -lbpf
```

## License
MIT license
