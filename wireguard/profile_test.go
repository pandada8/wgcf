package wireguard

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestNewSingBoxConfig(t *testing.T) {
	config, err := NewSingBoxConfig(&SingBoxProfileData{
		PrivateKey: "private",
		Address1:   "172.16.0.2",
		Address2:   "2606:4700::1",
		PublicKey:  "public",
		Endpoint:   "engage.cloudflareclient.com:2408",
		ClientID:   "2zBs",
	})
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{`"reserved":[219,48,108]`, `"port":2408`, `"address":"engage.cloudflareclient.com"`, `"172.16.0.2/32"`} {
		if !strings.Contains(string(encoded), expected) {
			t.Errorf("expected JSON to contain %s, got %s", expected, encoded)
		}
	}
}

func TestNewSingBoxConfigRejectsInvalidClientID(t *testing.T) {
	_, err := NewSingBoxConfig(&SingBoxProfileData{ClientID: "not-base64"})
	if err == nil {
		t.Fatal("expected invalid client_id error")
	}
}

func TestGenerateProfile(t *testing.T) {
	var expectedResult = `[Interface]
PrivateKey = 1
Address = 2/32, 3/128
DNS = 1.1.1.1, 1.0.0.1, 2606:4700:4700::1111, 2606:4700:4700::1001
MTU = 1280
[Peer]
PublicKey = 4
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 5
`

	result, err := generateProfile(&ProfileData{
		PrivateKey: "1",
		Address1:   "2",
		Address2:   "3",
		PublicKey:  "4",
		Endpoint:   "5",
	})
	if err != nil {
		t.Error(err)
	}

	if expectedResult != result {
		t.Error()
	}
}
