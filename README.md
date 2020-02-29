# netdev_bpf_progs
A tool for inspecting a netdev's BPF programs & maps

## Usage
```bash
./xsk_prog_map_info -i ${interface_name}
```

## Sample execution
```bash
./xsk_prog_map_info -i eno
# netdev BPF program information
        id: 14
        attached mode: XDP_ATTACHED_DRV - Attached with driver support
# netdev map information
map 1 of 1
        id: 13
        name: xsks_map
        type: XSK map
        flags: 0x0
```

## Tested on platform
| Software | Version   |
|----------|-----------|
| OS       | Debian 10 |
| Kernel   | 5.4.0     |
| GCC      | 8.3.0     |
| libbpf   | 0.0.7     |

## Prerequirements
Compile and install libbpf

## Compilation
```bash
export LD_LIBRARY_PATH=${path_of_libbpf
gcc -o xsk_prog_map_info xsk_prog_map_info.c -lbpf
```

## Todo
* Create test cases
* Maps meta data
* Option to scan all netdevs by default

## License
MIT
