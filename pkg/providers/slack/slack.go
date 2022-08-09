package slack

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/containrrr/shoutrrr"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/notify/pkg/types"
	"github.com/projectdiscovery/notify/pkg/utils"
)

type Provider struct {
	Options *Options `yaml:"slack,omitempty"`
}

type Options struct {
	ID              string `yaml:"id,omitempty"`
	SlackWebHookURL string `yaml:"slack_webhook_url,omitempty"`
	SlackUsername   string `yaml:"slack_username,omitempty"`
	SlackChannel    string `yaml:"slack_channel,omitempty"`
	SlackThreads    bool   `yaml:"slack_threads,omitempty"`
	SlackThreadTS   string `yaml:"slack_thread_ts,omitempty"`
	SlackToken      string `yaml:"slack_token,omitempty"`
	SlackFormat     string `yaml:"slack_format,omitempty"`
}

func New(options *Options) (*Provider, error) {
	provider := &Provider{Options: options}
	return provider, nil
}

func NewWithRaw(rawOptions *types.RawOptions) (*Provider, error) {
	options := Options{}
	err := rawOptions.Unmarshal(&options)
	if err != nil {
		return nil, err
	}
	return New(&options)
}

func (p *Provider) Send(message, CliFormat string) error {
	msg := utils.FormatMessage(message, utils.SelectFormat(CliFormat, p.Options.SlackFormat))

	if p.Options.SlackThreads {
		if p.Options.SlackToken == "" {
			return errors.Wrap(fmt.Errorf("slack_token value is required to start a thread"),
				fmt.Sprintf("failed to send slack notification for id: %s ", p.Options.ID))

		}
		if p.Options.SlackChannel == "" {
			return errors.Wrap(fmt.Errorf("slack_channel value is required to start a thread"),
				fmt.Sprintf("failed to send slack notification for id: %s ", p.Options.ID))
		}
		if err := p.Options.SendThreaded(msg); err != nil {
			return errors.Wrap(err,
				fmt.Sprintf("failed to send slack notification for id: %s ", p.Options.ID))
		}
	} else {
		slackTokens := strings.TrimPrefix(p.Options.SlackWebHookURL, "https://hooks.slack.com/services/")
		url := &url.URL{
			Scheme: "slack",
			Path:   slackTokens,
		}

		err := shoutrrr.Send(url.String(), msg)
		if err != nil {
			return errors.Wrap(err,
				fmt.Sprintf("failed to send slack notification for id: %s ", p.Options.ID))
		}
	}
	gologger.Verbose().Msgf("Slack notification sent successfully for id: %s", p.Options.ID)
	return nil
}
