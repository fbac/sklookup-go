/*
Copyright © 2022 Francisco de Borja Aranda Castillejo me@fbac.dev

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS bpf src/ebpf/sk_dispatch.c -- -Isrc/headers
package ebpf

import (
	"C"
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	pidfd "github.com/oraoto/go-pidfd"
	"github.com/rs/zerolog"
)

const (
	mapKey       uint32 = 0
	ebpfDir      string = "/sys/fs/bpf/"
	esock        string = "/sys/fs/bpf/sock"
	eport        string = "/sys/fs/bpf/port"
	dispatchProg string = "/sys/fs/bpf/dispatch_prog"
	dispatchLink string = "/sys/fs/bpf/dispatch_link"
)

// EbpfDispatcher represents an instance of the eBPF sk_lookup dispatcher
type EbpfDispatcher struct {
	Name            string
	Log             zerolog.Logger
	LogLevel        string
	AdditionalPorts []uint16
}

type EbpfInternalDispatcher struct {
	EbpfDispatcher
	FileDescriptor uintptr
}

type EbpfExternalDispatcher struct {
	EbpfDispatcher
	TargetPID int
}

// NewExternalDispatcher returns a new instance of external eBPF dispatcher
func NewExternalDispatcher(name string, pid int, ports []uint16, loglevel string) *EbpfExternalDispatcher {
	_, err := os.FindProcess(pid)
	if err != nil {
		panic(err)
	}
	return &EbpfExternalDispatcher{EbpfDispatcher: newEbpfDispatcher(name, ports, loglevel), TargetPID: pid}
}

// NewInternalDispatcher returns a new instance of internal eBPF dispatcher
func NewInternalDispatcher(name string, fd uintptr, ports []uint16, loglevel string) *EbpfInternalDispatcher {
	return &EbpfInternalDispatcher{EbpfDispatcher: newEbpfDispatcher(name, ports, loglevel), FileDescriptor: fd}
}

func newEbpfDispatcher(name string, ports []uint16, loglevel string) EbpfDispatcher {
	logger := newLogging(loglevel)

	if !checkValidPorts(ports) {
		logger.Fatal().Msgf("Ports provided not valid")
	}
	return EbpfDispatcher{Name: name, AdditionalPorts: ports, Log: logger}
}

// InitializeDispatcherByPID initializes sk_lookup on a given pid
func (e *EbpfExternalDispatcher) InitializeDispatcher() {
	ctx := newCancelableContext()
	e.Log.Info().Msgf("eBPF dispatcher with name %s initializing. Traffic from %v will be dispatched to PID %v", e.Name, e.AdditionalPorts, e.TargetPID)

	// Initialize custom vars, necessary to run more than one instance
	nameSockMap := fmt.Sprintf("%s-%s", esock, e.Name)
	namePortMap := fmt.Sprintf("%s-%s", eport, e.Name)
	nameDispatchProg := fmt.Sprintf("%s-%s", dispatchProg, e.Name)
	nameDispatchLink := fmt.Sprintf("%s-%s", dispatchLink, e.Name)
	if !checkFileDoNotExist(nameSockMap, namePortMap, nameDispatchProg, nameDispatchLink) {
		e.Log.Fatal().Msgf("Check that previous eBPF files doesn't exist: %s %s %s %s", nameSockMap, namePortMap, nameDispatchProg, nameDispatchLink)
	}

	// Allow locking memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		e.Log.Panic().Err(err).Msg("Unable to remove memlock")
	}

	// Load eBPF Program and Maps
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}
	defer objs.Close()

	// Pin eBPF program and maps
	if err := objs.SkDispatch.Pin(nameDispatchProg); err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to pin %v", nameDispatchProg)
	}
	defer objs.SkDispatch.Unpin()
	e.Log.Debug().Msgf("Prog %v is pinned: %v", objs.SkDispatch, objs.SkDispatch.IsPinned())

	if err := objs.TargetSocket.Pin(nameSockMap); err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to pin %v", nameSockMap)
	}
	defer objs.TargetSocket.Unpin()
	e.Log.Debug().Msgf("Map %s is pinned: %v", objs.TargetSocket, objs.TargetSocket.IsPinned())

	if err := objs.AddPorts.Pin(namePortMap); err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to pin %v", namePortMap)
	}
	defer objs.AddPorts.Unpin()
	e.Log.Debug().Msgf("Map %s is pinned: %v", objs.AddPorts, objs.AddPorts.IsPinned())

	// Check if there's a need of duplicating TargetPID file descriptors
	var fd uintptr
	if e.TargetPID != os.Getpid() {
		fd = e.getListenerFd()
	} else {
		e.Log.Panic().Msg("Calling InitializeDispatcherByPID is not allowed where TargetPID == os.Getpid()")
	}

	// Insert fd from listener in the SockMap
	if err := objs.TargetSocket.Put(mapKey, unsafe.Pointer(&fd)); err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to insert key %v into %v", fd, nameSockMap)
	}

	// Attach additional ports to the HashMap
	e.attachAdditionalPorts(objs.AddPorts)

	// Link, Pin and defer clean dispatch link
	lnk, err := getDispatcherLink(objs.SkDispatch)
	if err != nil {
		e.Log.Panic().Err(err).Msg("Unable to get dispatcher link")
	}
	lnk.Pin(nameDispatchLink)
	defer lnk.Close()
	defer lnk.Unpin()

	// Program fully initialized
	e.Log.Info().Msgf("eBPF dispatcher for app %s with PID %v initialized.", e.Name, e.TargetPID)

	// Wait until done
	<-ctx.Done()
}

// InitializeDispatcherByFD initializes the sk_lookup on a given socket fd
func (e *EbpfInternalDispatcher) InitializeDispatcher() {
	ctx := newCancelableContext()
	e.Log.Info().Msgf("eBPF dispatcher with name %s initializing. Traffic from %v will be dispatched to FD %v", e.Name, e.AdditionalPorts, e.FileDescriptor)

	// Initialize custom vars, necessary to run more than one instance
	nameSockMap := fmt.Sprintf("%s-%s", esock, e.Name)
	namePortMap := fmt.Sprintf("%s-%s", eport, e.Name)
	nameDispatchProg := fmt.Sprintf("%s-%s", dispatchProg, e.Name)
	nameDispatchLink := fmt.Sprintf("%s-%s", dispatchLink, e.Name)
	if !checkFileDoNotExist(nameSockMap, namePortMap, nameDispatchProg, nameDispatchLink) {
		e.Log.Fatal().Msgf("Check that previous eBPF files doesn't exist: %s %s %s %s", nameSockMap, namePortMap, nameDispatchProg, nameDispatchLink)
	}

	// Allow locking memory for eBPF resources
	if err := rlimit.RemoveMemlock(); err != nil {
		e.Log.Panic().Err(err).Msg("Unable to remove memlock")
	}

	// Load eBPF Program and Maps
	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		log.Fatalf("loading objects: %v", err)
	}

	// Pin eBPF program and maps
	if err := objs.SkDispatch.Pin(nameDispatchProg); err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to pin %v", nameDispatchProg)
	}
	e.Log.Debug().Msgf("Prog %v is pinned: %v", objs.SkDispatch, objs.SkDispatch.IsPinned())

	if err := objs.TargetSocket.Pin(nameSockMap); err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to pin %v", nameSockMap)
	}
	e.Log.Debug().Msgf("Map %s is pinned: %v", objs.TargetSocket, objs.TargetSocket.IsPinned())

	if err := objs.AddPorts.Pin(namePortMap); err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to pin %v", namePortMap)
	}
	e.Log.Debug().Msgf("Map %s is pinned: %v", objs.AddPorts, objs.AddPorts.IsPinned())

	// Insert fd from listener in the SockMap
	if err := objs.TargetSocket.Put(mapKey, unsafe.Pointer(&e.FileDescriptor)); err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to insert key %v into %v", e.FileDescriptor, nameSockMap)
	}

	// Attach additional ports to the HashMap
	e.attachAdditionalPorts(objs.AddPorts)

	// Link, Pin and defer clean dispatch link
	lnk, err := getDispatcherLink(objs.SkDispatch)
	if err != nil {
		e.Log.Panic().Err(err).Msg("Unable to get dispatcher link")
	}
	lnk.Pin(nameDispatchLink)

	// Program fully initialized
	e.Log.Info().Msgf("eBPF dispatcher for app %s with FD %v initialized.", e.Name, e.FileDescriptor)

	// Housekeeping
	defer objs.Close()
	defer lnk.Close()
	defer objs.SkDispatch.Unpin()
	defer objs.TargetSocket.Unpin()
	defer objs.AddPorts.Unpin()
	defer lnk.Unpin()

	// Wait until done
	<-ctx.Done()
}

// getListenerFd opens a file descriptor and duplicates it to be used by the eBPF program
// This is an abstraction of the systemcall pidfd_getfd(pidfd_open(PID, 0), FD, 0)
func (e *EbpfExternalDispatcher) getListenerFd() uintptr {
	// pidfd_open
	pidFd, err := pidfd.Open(e.TargetPID, 0)
	if err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to open target pid %v", e.TargetPID)
	}
	e.Log.Trace().Msgf("getListenerFd.pidFd: %v", pidFd)

	// pidfd_getfd
	listenFd, err := pidFd.GetFd(int(pidFd), 0)
	if err != nil {
		e.Log.Panic().Err(err).Msgf("Unable to duplicate target fd %v", pidFd)
	}
	e.Log.Trace().Msgf("getListenerFd.listenFd: %v", listenFd)

	file := os.NewFile(uintptr(listenFd), "")

	return file.Fd()
}

// attachAdditionalPorts inserts additional ports into the ports HashMap
func (e *EbpfDispatcher) attachAdditionalPorts(hashMap *ebpf.Map) {
	for _, v := range e.AdditionalPorts {
		e.Log.Debug().Msgf("adding port: %v", v)
		if err := hashMap.Put(v, uint8(0)); err != nil {
			panic(err)
		}
	}
}

// getDispatcherLink links the self netnamespace to the link
// so the communication to the external socket can happen
func getDispatcherLink(p *ebpf.Program) (*link.NetNsLink, error) {
	// Get self net-namespace
	netns, err := os.Open("/proc/self/ns/net")
	if err != nil {
		return nil, err
	}
	defer netns.Close()

	// Attach the network namespace to the link
	lnk, err := link.AttachNetNs(int(netns.Fd()), p)
	if err != nil {
		return nil, err
	}

	return lnk, nil
}

// checkFileDoNotExist check if provided files don't exist
func checkFileDoNotExist(files ...string) bool {
	for _, v := range files {
		if _, err := os.Stat(v); err == nil {
			return true
		}
	}
	return false
}

func checkValidPorts(p []uint16) bool {
	return len(p) >= 0
}

// newCancelableContext returns a context that gets canceled by a SIGINT
func newCancelableContext() context.Context {
	doneCh := make(chan os.Signal, 1)
	signal.Notify(doneCh, os.Interrupt)

	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)

	go func() {
		<-doneCh
		cancel()
	}()

	return ctx
}

func newLogging(loglevel string) zerolog.Logger {
	logger := zerolog.New(os.Stderr).With().Timestamp().Logger()
	switch loglevel {
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
	return logger
}
