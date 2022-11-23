# scan open ports
nmap -sT -p 1-10000 192.168.122.202

# ssh test connection
ssh -p 22 ubuntu@192.168.122.202 'hostname'
ssh -p 222 ubuntu@192.168.122.202 'hostname'

# retrieve sshd pid, socket and file descriptor
ss -tulpn4 | grep sshd

# show sklookup-go usage
sklookup start

# run sklookup-go
sklookup start -l debug -n sshd-sklookup --pid 1410 -p 222,1111,2641 &

# retrieve sshd pid, socket and file descriptor
ss -tulpn4 | grep sshd

# scan open ports
nmap -sT -p 1-10000 192.168.122.202

# bpftool to check pinned program
bpftool prog show pinned dispatch_prog-sshd-sklookup

# bpftool to check pinned maps
bpftool map show id 9
bpftool map show id 10


# bpftool to dump data from maps
bpftool map dump pinned sock-sshd-sklookup
bpftool map dump pinned port-sshd-sklookup

# ssh test connection to unusual port
ssh -p 2641 ubuntu@192.168.122.202 'hostname'
ssh -p 2641 ubuntu@192.168.122.202