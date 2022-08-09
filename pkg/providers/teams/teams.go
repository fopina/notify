package teams

import (
	"fmt"
	"strings"

	"github.com/containrrr/shoutrrr"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/notify/pkg/utils"
)

type Provider struct {
	Options *Options `yaml:"teams,omitempty"`
}

type Options struct {
	ID              string `yaml:"id,omitempty"`
	TeamsWebHookURL string `yaml:"teams_webhook_url,omitempty"`
	TeamsFormat     string `yaml:"teams_format,omitempty"`
}

func New(options *Options) (*Provider, error) {
	provider := &Provider{Options: options}
	return provider, nil
}

func (p *Provider) Send(message, CliFormat string) error {
	msg := utils.FormatMessage(message, utils.SelectFormat(CliFormat, p.Options.TeamsFormat))

	teamsTokens := strings.TrimPrefix(p.Options.TeamsWebHookURL, "https://outlook.office.com/webhook/")
	teamsTokens = strings.ReplaceAll(teamsTokens, "IncomingWebhook/", "")
	url := fmt.Sprintf("teams://%s", teamsTokens)
	err := shoutrrr.Send(url, msg)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to send teams notification for id: %s ", p.Options.ID))
	}
	gologger.Verbose().Msgf("teams notification sent for id: %s", p.Options.ID)
	return nil
}
