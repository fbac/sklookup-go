package main

import (
	ebpf "github.com/fbac/sklookup-go/pkg/ebpf"
)

func main() {
	name := "ssh"
	pid := 165929
	ports := []uint16{222, 2222, 1111}
	loglevel := "debug"

	ebpf.NewEbpfDispatcher(name, pid, ports, loglevel).InitializeDispatcher()
}
