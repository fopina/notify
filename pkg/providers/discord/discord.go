package discord

import (
	"fmt"

	"github.com/containrrr/shoutrrr"
	"github.com/oriser/regroup"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/notify/pkg/utils"
)

type Provider struct {
	Options *Options `yaml:"discord,omitempty"`
}

type Options struct {
	ID                      string `yaml:"id,omitempty"`
	DiscordWebHookURL       string `yaml:"discord_webhook_url,omitempty"`
	DiscordWebHookUsername  string `yaml:"discord_username,omitempty"`
	DiscordWebHookAvatarURL string `yaml:"discord_avatar,omitempty"`
	DiscordFormat           string `yaml:"discord_format,omitempty"`
}

func New(options *Options) (*Provider, error) {
	provider := &Provider{Options: options}
	return provider, nil
}

func (p *Provider) Send(message, CliFormat string) error {
	msg := utils.FormatMessage(message, utils.SelectFormat(CliFormat, p.Options.DiscordFormat))

	discordWebhookRegex := regroup.MustCompile(`(?P<scheme>https?):\/\/(?P<domain>(?:ptb\.|canary\.)?discord(?:app)?\.com)\/api(?:\/)?(?P<api_version>v\d{1,2})?\/webhooks\/(?P<webhook_identifier>\d{17,19})\/(?P<webhook_token>[\w\-]{68})`)
	matchedGroups, err := discordWebhookRegex.Groups(p.Options.DiscordWebHookURL)
	if err != nil {
		return fmt.Errorf("incorrect discord configuration for id: %s ", p.Options.ID)
	}

	webhookID, webhookToken := matchedGroups["webhook_identifier"], matchedGroups["webhook_token"]
	url := fmt.Sprintf("discord://%s@%s?splitlines=no", webhookToken, webhookID)
	sendErr := shoutrrr.Send(url, msg)
	if sendErr != nil {
		return errors.Wrap(sendErr, fmt.Sprintf("failed to send discord notification for id: %s ", p.Options.ID))
	}
	gologger.Verbose().Msgf("discord notification sent for id: %s", p.Options.ID)
	return nil
}
