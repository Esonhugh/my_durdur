# Durdur

[Durdur](https://www.youtube.com/watch?v=sF0QweCoaMo) is a CLI tool for Linux implementing L4 package dropping with eBPF/Go (proof of concept).

## How to install

### From source;

Build and use `build/durdur` binary.

```
make build
```

## How to Use

```shell
# ./build/durdur help   
Durdur is a L4 package Dropper/Firewall.

Usage:
  durdur [command]

Available Commands:
  attach      Attaches the program to the network.
  completion  Generate the autocompletion script for the specified shell
  detach      Detaches the program from the network.
  drop        Add new IP/port to the maps.
  help        Help about any command
  list        List all the rules
  log         print logs of dropping data
  undrop      Add new IP/port to the maps.

Flags:
  -b, --bpffs string   mounted bpffs location (default "/sys/fs/bpf")
  -d, --debug          Enable debug mode
  -h, --help           help for durdur

Use "durdur [command] --help" for more information about a command.
```

### Attach to interface

```shell  
./build/durdur attach -i eth0 -d
INFO[0000] Trying to attach XDP and TC eBPF program to the eth0. 
INFO[0000] Load XDP eBPF program successfully           
INFO[0000] Load TC eBPF program successfully     
```

### Detach from interface

```shell
./build/durdur detach
INFO[0000] Load XDP eBPF program successfully           
INFO[0000] Load TC eBPF program successfully            
INFO[0000] Detached from the network.     
```

### Add a drop rule

```shell
# ./build/durdur drop --dst -i 198.19.249.98 -p 8000
INFO[0000] Load XDP eBPF program successfully           
INFO[0000] Load TC eBPF program successfully            
INFO[0000] MapOperation: add dst 198.19.249.98 8000   
# ./build/durdur drop --dst -i 198.19.249.97        
INFO[0000] Load XDP eBPF program successfully           
INFO[0000] Load TC eBPF program successfully            
INFO[0000] MapOperation: add dst 198.19.249.97 0 
# ./build/durdur drop --src -i 198.19.249.97
INFO[0000] Load XDP eBPF program successfully           
INFO[0000] Load TC eBPF program successfully            
INFO[0000] MapOperation: add src 198.19.249.97 0  
```

### List all rules

```shell
# ./build/durdur list                       
INFO[0000] Load XDP eBPF program successfully           
INFO[0000] Load TC eBPF program successfully            
INFO[0000] --ingress-> world 198.19.249.97:any hint-rule:0 
INFO[0000] world <-egress-- 198.19.249.97:any hint-rule:0 
INFO[0000] world <-egress-- 198.19.249.98:8000 hint-rule:0 
```

### Del a drop rule

```shell
#  ./build/durdur undrop --src -i 198.19.249.97
INFO[0000] Load XDP eBPF program successfully           
INFO[0000] Load TC eBPF program successfully            
INFO[0000] MapOperation: del src 198.19.249.97 0 
```

### Print logs

```shell
# ./build/durdur log
INFO[0000] Load XDP eBPF program successfully           
INFO[0000] Load TC eBPF program successfully            
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:46279 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:5790 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:5790 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:5790 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:5790 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:5790 to 198.19.249.98:16415 
Dropped Packect from 198.19.249.193:5790 to 198.19.249.98:16415 
```


## Copyright

[GPL-3.0 license](https://github.com/boratanrikulu/durdur/blob/main/LICENSE),  
Copyright 2022 Bora Tanrikulu <[me@bora.sh](mailto:me@bora.sh)>
Copyright 2024 Esonhugh <[durdur-project@eson.ninja](mailto:durdur-project@eson.ninja)>