package pushover

import (
	"fmt"
	"strings"

	"github.com/containrrr/shoutrrr"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/notify/pkg/utils"
)

type Provider struct {
	Options *Options `yaml:"pushover,omitempty"`
}

type Options struct {
	ID               string   `yaml:"id,omitempty"`
	PushoverApiToken string   `yaml:"pushover_api_token,omitempty"`
	UserKey          string   `yaml:"pushover_user_key,omitempty"`
	PushoverDevices  []string `yaml:"pushover_devices,omitempty"`
	PushoverFormat   string   `yaml:"pushover_format,omitempty"`
}

func New(options *Options) (*Provider, error) {
	provider := &Provider{Options: options}
	return provider, nil
}

func (p *Provider) Send(message, CliFormat string) error {
	msg := utils.FormatMessage(message, utils.SelectFormat(CliFormat, p.Options.PushoverFormat))

	url := fmt.Sprintf("pushover://shoutrrr:%s@%s/?devices=%s", p.Options.PushoverApiToken, p.Options.UserKey, strings.Join(p.Options.PushoverDevices, ","))
	err := shoutrrr.Send(url, msg)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to send pushover notification for id: %s ", p.Options.ID))
	}
	gologger.Verbose().Msgf("pushover notification sent for id: %s", p.Options.ID)
	return nil
}
