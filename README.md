# sklookup-go

- [sklookup-go](#sklookup-go)
  - [What is sk_lookup](#what-is-sk_lookup)
  - [Use cases](#use-cases)
  - [Requirements](#requirements)
  - [Usage](#usage)
    - [As golang package](#as-golang-package)
    - [As cli](#as-cli)
    - [Tested OS, kernels and libbpf](#tested-os-kernels-and-libbpf)
      - [Ubuntu 22.04.1 LTS - Jammy](#ubuntu-22041-lts---jammy)
      - [Fedora release 36 (Thirty Six)](#fedora-release-36-thirty-six)
  - [To Do](#to-do)
  - [Demonstration](#demonstration)

## What is sk_lookup

**WIP Section**

Fast introduction to technologies used:

  - eBPF
  - BTF
  - bpf2go
  - sk_lookup <https://www.kernel.org/doc/html/latest/bpf/prog_sk_lookup.html>

## Use cases

**WIP Section**

- Attaching ports to an already running service
- Serving applications from multiple ports while binding only to one
- Ideal solution for proxies
- Rule of cool: why not use eBPF when it's just simply so cool?

## Requirements

- golang 1.18
- libbpf
- libbpf-dev

## Usage

### As golang package

- Use as library, from your go code

```go
import "github.com/fbac/sklookup-go/pkg/ebpf"

func main() {
 name := "AppName"
 pid := 165929
 ports := []uint16{222, 2222, 1111, 7878}
 loglevel := "debug"

 ebpf.NewEbpfDispatcher(name, pid, ports, loglevel).InitializeDispatcher()
}
```

### As cli

- Build

```bash
make build-cli
```

- Usage options
  - Note that `sk` must be run as root, since it requires loading eBPF programs and maps into kernel memory. Otherwise your system should allow unprivileged eBPF code, and that's not secure and not a scope of this project.

```bash
$ sudo bin/sk start -h

Start targets a PID, and steer all the connections from the provided additional ports to the socket where it's listening

Usage:
  sk start [flags]

Flags:
  -h, --help              help for start
  -l, --loglevel string   Log-level to run the app. Available: info, debug, panic. (default "info")
  -n, --name string       Descriptive name for the application (default "sk_lookup")
      --pid int           Target process PID (default -1)
  -p, --ports uints       Additional ports (default [])
  -t, --toggle            Help message for toggle
```

### Tested OS, kernels and libbpf

The proxy has been tested in the following OS, with the respective kernel and bpf tools versions.

Also, it's **required** to run it as **root** user.

The system must be able to run BPF programs.

#### Ubuntu 22.04.1 LTS - Jammy

- Kernel `5.15.0-47-generic`

- golang 1.18

- BPF packages:

```bash
binutils-bpf/jammy 2.38-2ubuntu1+3 amd64
bpftrace/jammy 0.14.0-1 amd64
libbpf-dev/jammy 1:0.5.0-1 amd64
libbpf0/jammy,now 1:0.5.0-1 amd64 [installed,automatic]
```

#### Fedora release 36 (Thirty Six)

- Kernel `5.18.17-200.fc36.x86_64`
- golang 1.18
- BPF packages:

```bash
libbpf-0.7.0-3.fc36.x86_64
libbpf-devel-0.7.0-3.fc36.x86_64
bpftrace-0.14.1-1.fc36.x86_64
bpftool-5.19.4-200.fc36.x86_64
```

## To Do

- Use os.Env to supply parameters
- Include test suite
- Polish Makefile
- Finish README.md

## Demonstration

Let's add additional ports to an old good sshd server

Said sshd server is running inside a virtual machine.

- Scanning open ports

```bash
# nmap -sT -p 1-10000 192.168.122.172

Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 16:21 CEST
Nmap scan report for 192.168.122.172
Host is up (0.00020s latency).
Not shown: 9999 closed tcp ports (conn-refused)
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 52:54:00:74:4B:83 (QEMU virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.66 seconds
```

- Build `sk` and copy into the vm

```bash
$ make build-cli

# sklook build started
mkdir -p bin
go build -o bin/sk .

$ scp bin/sk root@192.168.122.172:/tmp
sk 100% 5709KB  17.6MB/s   00:00 
```

- Login into the vm and get sshd PID

```bash
$ pidof sshd
627
```

- Run `sk` against the target PID and with as many as additional ports as needed. (max ports 1024)

```bash
root@vm:~# /tmp/sk start --pid 627 --ports 2,22,222,1111,1010,9999 --name sshd-vm --loglevel debug &
[1] 2109

root@vm:~# {"level":"info","time":"2022-09-19T14:27:40Z","message":"eBPF dispatcher with name sshd-vm initializing"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"Prog SkLookup(sk_dispatch)#6 is pinned: true"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"Map SockMap(target_socket)#5 is pinned: true"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"Map Hash(add_ports)#4 is pinned: true"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"listener FD: 7"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"adding port: 2"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"adding port: 22"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"adding port: 222"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"adding port: 1111"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"adding port: 1010"}
{"level":"debug","time":"2022-09-19T14:27:40Z","message":"adding port: 9999"}
{"level":"info","time":"2022-09-19T14:27:40Z","message":"eBPF dispatcher sshd-vm initialized. Dispatching traffic from ports [2 22 222 1111 1010 9999] to original pid 627"}
```

- From your host, scan again the vm open ports

```bash
[root@hyperion ~]# nmap -sT -p 1-10000 192.168.122.172
Starting Nmap 7.92 ( https://nmap.org ) at 2022-09-19 16:29 CEST
Nmap scan report for 192.168.122.172
Host is up (0.00019s latency).
Not shown: 9994 closed tcp ports (conn-refused)
PORT     STATE SERVICE
2/tcp    open  compressnet
22/tcp   open  ssh
222/tcp  open  rsh-spx
1010/tcp open  surf
1111/tcp open  lmsocialserver
9999/tcp open  abyss
MAC Address: 52:54:00:74:4B:83 (QEMU virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 0.49 seconds
```

- Try to connect to any of them

```bash
[root@localhost ~]# ssh root@192.168.122.172 -p 9999

The authenticity of host '[192.168.122.172]:9999 ([192.168.122.172]:9999)' can't be established.
ED25519 key fingerprint is SHA256:MsHOzsCjHKvahbf45QnFgxpEaIF7mdhCWGiKOs8vPns.
This key is not known by any other names
Are you sure you want to continue connecting (yes/no/[fingerprint])?
```

- In the vm, the pinned eBPF program and maps are pinned in a bpf filesystem

```bash
root@proxy-last:~# ls -l //sys/fs/bpf/
total 0
-rw------- 1 root root 0 Sep 19 14:27 dispatch_link-sshd-vm
-rw------- 1 root root 0 Sep 19 14:27 dispatch_prog-sshd-vm
-rw------- 1 root root 0 Sep 19 14:27 port-sshd-vm
-rw------- 1 root root 0 Sep 19 14:27 sock-sshd-vm
```

- Also, the eBPF program and maps can be debugged as usual using `bpftool`

```bash
[root@localhost ~]#  bpftool prog show pinned /sys/fs/bpf/dispatch_prog-sshd-vm

201: sk_lookup  name sk_dispatch  tag da043673afd29081  gpl
 loaded_at 2022-09-19T16:34:02+0200  uid 0
 xlated 272B  jited 156B  memlock 4096B  map_ids 270,271
 btf_id 380
 pids sk(423122)
```

- Check pinned maps by id (or by path)

```bash
[root@localhost ~]# bpftool map show id 271

271: sockmap  name target_socket  flags 0x0
 key 4B  value 8B  max_entries 1  memlock 4096B
 pids sk(423122)
```

- Check map contents

```bash
[root@hyperion ~]#  bpftool map dump pinned /sys/fs/bpf/sock-sshd-vm 
key: 00 00 00 00  value: 04 20 00 00 00 00 00 00
Found 1 element
```

```bash
[root@hyperion ~]#  bpftool map dump pinned /sys/fs/bpf/port-sshd-vm $
[{
        "key": 1010,
        "value": 0
    },{
        "key": 9999,
        "value": 0
    },{
        "key": 22,
        "value": 0
    },{
        "key": 1111,
        "value": 0
    },{
        "key": 222,
        "value": 0
    },{
        "key": 2,
        "value": 0
    }
}]
```
