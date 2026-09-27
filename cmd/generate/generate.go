package generate

import (
	"log"

	"github.com/ViRb3/wgcf/v2/cloudflare"
	. "github.com/ViRb3/wgcf/v2/cmd/shared"
	"github.com/ViRb3/wgcf/v2/config"
	"github.com/ViRb3/wgcf/v2/wireguard"
	"github.com/cockroachdb/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var profileFile string
var outputFormat string
var shortMsg = "Generates a WireGuard profile from the current Cloudflare Warp account"

var Cmd = &cobra.Command{
	Use:   "generate",
	Short: shortMsg,
	Long:  FormatMessage(shortMsg, ``),
	Run: func(cmd *cobra.Command, args []string) {
		RunCommandFatal(generateProfile)
	},
}

func init() {
	Cmd.PersistentFlags().StringVarP(&profileFile, "profile", "p", "wgcf-profile.conf", "Output profile file")
	Cmd.PersistentFlags().StringVar(&outputFormat, "format", "wireguard", "Output format: wireguard or sing-box")
}

func generateProfile() error {
	if err := EnsureConfigValidAccount(); err != nil {
		return errors.WithStack(err)
	}

	if outputFormat != "wireguard" && outputFormat != "sing-box" {
		return errors.New("format must be either wireguard or sing-box")
	}
	if outputFormat == "sing-box" && profileFile == "wgcf-profile.conf" {
		profileFile = "wgcf-profile.json"
	}

	ctx := CreateContext()
	thisDevice, err := cloudflare.GetSourceDevice(ctx)
	if err != nil {
		return errors.WithStack(err)
	}

	data := &wireguard.ProfileData{
		PrivateKey: viper.GetString(config.PrivateKey),
		Address1:   thisDevice.Config.Interface.Addresses.V4,
		Address2:   thisDevice.Config.Interface.Addresses.V6,
		PublicKey:  thisDevice.Config.Peers[0].PublicKey,
		Endpoint:   thisDevice.Config.Peers[0].Endpoint.Host,
	}

	if outputFormat == "sing-box" {
		singBox, err := wireguard.NewSingBoxConfig(&wireguard.SingBoxProfileData{
			PrivateKey: data.PrivateKey,
			Address1:   data.Address1,
			Address2:   data.Address2,
			PublicKey:  data.PublicKey,
			Endpoint:   data.Endpoint,
			ClientID:   thisDevice.Config.ClientId,
		})
		if err != nil {
			return errors.WithStack(err)
		}
		if err := singBox.Save(profileFile); err != nil {
			return errors.WithStack(err)
		}
	} else {
		profile, err := wireguard.NewProfile(data)
		if err != nil {
			return errors.WithStack(err)
		}
		if err := profile.Save(profileFile); err != nil {
			return errors.WithStack(err)
		}
	}

	log.Println("Successfully generated WireGuard profile:", profileFile)
	return nil
}
