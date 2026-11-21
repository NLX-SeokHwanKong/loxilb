// SPDX-License-Identifier: Apache-2.0
package loxinet

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// A root coordinator holds exclusive ownership of both gates through final
// readback and publication. A BFD notification alone never starts this service.
type cidHandoffConfig struct {
	vip   net.IP
	ports []string
	zone  int
}

type cidHandoffRequest struct {
	VIP  string `json:"vip"`
	Port uint16 `json:"port"`
	Rule uint32 `json:"rule"`
}

type cidHandoffReply struct {
	CT    uint32 `json:"ct"`
	FC    uint32 `json:"fc"`
	Error string `json:"error,omitempty"`
}

func startCIDHandoff(spec string, zone int) error {
	addr, ports, ok := strings.Cut(spec, "@")
	cfg := cidHandoffConfig{net.ParseIP(addr).To4(), strings.Split(ports, ","), zone}
	if !ok || cfg.vip == nil || !cfg.vip.IsGlobalUnicast() || len(cfg.ports) != 2 || cfg.ports[0] == cfg.ports[1] || zone <= 0 || zone > 65535 {
		return fmt.Errorf("expected IPv4 VIP and two distinct data interfaces")
	}
	for _, name := range cfg.ports {
		dev, err := net.InterfaceByName(name)
		if err != nil || dev.Flags&net.FlagLoopback != 0 {
			return fmt.Errorf("invalid data interface %q", name)
		}
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: "@loxilb-cid-handoff-v1", Net: "unixpacket"})
	if err != nil {
		return err
	}
	go func() {
		defer listener.Close()
		for {
			conn, err := listener.AcceptUnix()
			if err != nil {
				return
			}
			cfg.serve(conn)
			conn.Close()
		}
	}()
	return nil
}

func (cfg cidHandoffConfig) fenced() error {
	for _, name := range cfg.ports {
		carrier, err := os.ReadFile(filepath.Join("/sys/class/net", name, "carrier"))
		if err != nil || strings.TrimSpace(string(carrier)) != "0" {
			return fmt.Errorf("carrier not confirmed down on %s", name)
		}
	}
	return nil
}

func (cfg cidHandoffConfig) serve(conn *net.UnixConn) {
	raw, err := conn.SyscallConn()
	if err != nil {
		return
	}
	var cred *unix.Ucred
	if raw.Control(func(fd uintptr) { cred, _ = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || cred == nil || cred.Uid != 0 {
		return
	}
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	var packet [256]byte
	n, _, flags, _, err := conn.ReadMsgUnix(packet[:], nil)
	if err != nil || flags&unix.MSG_TRUNC != 0 {
		return
	}
	var req cidHandoffRequest
	var reply cidHandoffReply
	if err = json.Unmarshal(bytes.TrimSpace(packet[:n]), &req); err == nil {
		if !net.ParseIP(req.VIP).Equal(cfg.vip) || req.Port == 0 || req.Rule == 0 {
			err = fmt.Errorf("invalid handoff scope")
		}
	}
	if err == nil {
		err = cfg.fenced()
	}
	if err == nil {
		reply.CT, reply.FC, err = drainCIDService(cfg.vip, cfg.zone, req.Port, req.Rule)
	}
	if err == nil {
		err = cfg.fenced()
	}
	if err != nil {
		reply.Error = err.Error()
	}
	json.NewEncoder(conn).Encode(reply)
}
