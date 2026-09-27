package wireguard

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

type SingBoxConfig struct {
	Type       string        `json:"type"`
	Tag        string        `json:"tag"`
	MTU        int           `json:"mtu"`
	Peers      []SingBoxPeer `json:"peers"`
	Address    []string      `json:"address"`
	PrivateKey string        `json:"private_key"`
}

type SingBoxPeer struct {
	PublicKey                   string   `json:"public_key"`
	Reserved                    []int    `json:"reserved"`
	PersistentKeepaliveInterval int      `json:"persistent_keepalive_interval"`
	AllowedIPs                  []string `json:"allowed_ips"`
	Address                     string   `json:"address"`
	Port                        int      `json:"port"`
}

type SingBoxProfileData struct {
	PrivateKey string
	Address1   string
	Address2   string
	PublicKey  string
	Endpoint   string
	ClientID   string
}

func NewSingBoxConfig(data *SingBoxProfileData) (*SingBoxConfig, error) {
	reserved, err := base64.StdEncoding.DecodeString(data.ClientID)
	if err != nil {
		return nil, fmt.Errorf("decode client_id %q: %w", data.ClientID, err)
	}
	if len(reserved) != 3 {
		return nil, fmt.Errorf("client_id %q decodes to %d bytes, expected 3", data.ClientID, len(reserved))
	}

	host, portString, err := net.SplitHostPort(data.Endpoint)
	if err != nil {
		return nil, fmt.Errorf("parse endpoint %q: %w", data.Endpoint, err)
	}
	port, err := strconv.Atoi(portString)
	if err != nil || port < 1 || port > 65535 {
		return nil, fmt.Errorf("invalid endpoint port %q", portString)
	}

	reservedInts := make([]int, len(reserved))
	for i, value := range reserved {
		reservedInts[i] = int(value)
	}

	return &SingBoxConfig{
		Type: "wireguard",
		Tag:  "warp",
		MTU:  1420,
		Peers: []SingBoxPeer{{
			PublicKey:                   data.PublicKey,
			Reserved:                    reservedInts,
			PersistentKeepaliveInterval: 30,
			AllowedIPs:                  []string{"0.0.0.0/0", "::/0"},
			Address:                     strings.Trim(host, "[]"),
			Port:                        port,
		}},
		Address:    []string{data.Address1 + "/32", data.Address2 + "/128"},
		PrivateKey: data.PrivateKey,
	}, nil
}

func (c *SingBoxConfig) Save(path string) error {
	contents, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, contents, 0600)
}
