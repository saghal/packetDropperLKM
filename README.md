# Firewall

### implement a loadable kernel module
## overview
we have two config :
  - blacklist
> we have some ip:port , if recieved packet match with blacklist ip's we drop recieved packet else we accept  recieved packet
  - whitelist
> we have some ip:port , if recieved packet match with whitelist ip's we accept recieved packet else we drop recieved packet

## Codes

[./sourcecodes/netLKM.c](https://github.com/saghal/packetDropperLKM/blob/master/sourcecodes/netLKM.c) : main code
[./sourcecodes/TestNetLKM.c](https://github.com/saghal/packetDropperLKM/blob/master/sourcecodes/testNetLKM.c) : tester code send ip:port to module
[./sourcecodes/Makefile](https://github.com/saghal/packetDropperLKM/blob/master/sourcecodes/Makefile) : makefile
[./sourcecodes/config.txt](https://github.com/saghal/packetDropperLKM/blob/master/sourcecodes/config.txt) : choose policy and enter ip:ports
#####

## Run
#### 1 : make and compile tester
```sh
$ make
```

#### 2 : load module
```sh
$ sudo insmode netLKM.ko
```

#### 3 : run tester
```sh
$ sudo ./test
```

####  4  : see kernel log
```sh
$ journalctl -f
```


## unload module

#### 1 : unload
```sh
$ sudo rmmod netLKM
```
#### 2 : clean
```sh
$ make clean
```

### procedure

* ### testNetLKM.c
in this file we first open `config.txt` and device module
and after that we read from this file and in first line we choose our policy `blacklist` or `whitelist`
and line by line read from this file and send ip:port to device module
int this file our goal is run it for an interface between module and user
* ### netLKM.c
we have two necessary function in module `init` and `exit` in order first function for register module  , for identify this device from user we declare major and minor number ,this numbers unique and with this number user identify moudle and after that and we must create class device and after that create device for connect with user and after this register we
for filtering net must declare this  nf_register_net_hook() for register net filter
and exit function for unregistter module from kernel

nf_hook_ops packetDropper()
for identify just ipv4 packet and define packetDropper_hook() for after identify ipv4 filter with ip and port
we need overwrite some function like open , release , write

`Note: for naming we must be careful`  
.open = dev_Open()
in this function we open devcie
.release = dev_release()
in this function we closed device
.write = dev_write()
int this function we catch information from user(tester) and store config and ip:port recievd

packetDropper_hook()
this is main function we do drop or accept packets
use stored information from dev_write we first go our policy and after that from recievd ip if that in whitelist we accept else we dropped
if recieved ip in blacklist we drop that else we accept that

`warning : when we use fgets that append a \n end of line for solve this problem we -1 size of recived informations to
Deactivate \n`


### Resources
[derek molloy](http://derekmolloy.ie/writing-a-linux-kernel-module-part-2-a-character-device/)
[ICMPdropko](https://github.com/payamnaghdy/ICMPdropko)
