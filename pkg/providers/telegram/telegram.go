package telegram

import (
	"fmt"

	"github.com/containrrr/shoutrrr"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/notify/pkg/utils"
)

type Provider struct {
	Options *Options `yaml:"telegram,omitempty"`
}

type Options struct {
	ID             string `yaml:"id,omitempty"`
	TelegramAPIKey string `yaml:"telegram_api_key,omitempty"`
	TelegramChatID string `yaml:"telegram_chat_id,omitempty"`
	TelegramFormat string `yaml:"telegram_format,omitempty"`
}

func New(options *Options, ids []string) (*Provider, error) {
	provider := &Provider{Options: options}
	return provider, nil
}

func (p *Provider) Send(message, CliFormat string) error {
	msg := utils.FormatMessage(message, utils.SelectFormat(CliFormat, p.Options.TelegramFormat))

	url := fmt.Sprintf("telegram://%s@telegram?channels=%s", p.Options.TelegramAPIKey, p.Options.TelegramChatID)
	err := shoutrrr.Send(url, msg)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to send telegram notification for id: %s ", p.Options.ID))
	}
	gologger.Verbose().Msgf("telegram notification sent for id: %s", p.Options.ID)
	return nil
}
