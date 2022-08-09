package custom

import (
	"bytes"
	"fmt"
	"net/http"

	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/notify/pkg/utils"
	"github.com/projectdiscovery/notify/pkg/utils/httpreq"
)

type Provider struct {
	Options *Options `yaml:"custom,omitempty"`
}

type Options struct {
	ID               string            `yaml:"id,omitempty"`
	CustomWebhookURL string            `yaml:"custom_webook_url,omitempty"`
	CustomMethod     string            `yaml:"custom_method,omitempty"`
	CustomHeaders    map[string]string `yaml:"custom_headers,omitempty"`
	CustomFormat     string            `yaml:"custom_format,omitempty"`
}

func New(options *Options) (*Provider, error) {
	provider := &Provider{Options: options}
	return provider, nil
}

func (p *Provider) Send(message, CliFormat string) error {
	msg := utils.FormatMessage(message, utils.SelectFormat(CliFormat, p.Options.CustomFormat))
	body := bytes.NewBufferString(msg)

	r, err := http.NewRequest(p.Options.CustomMethod, p.Options.CustomWebhookURL, body)
	if err != nil {
		err = errors.Wrap(err, fmt.Sprintf("failed to send custom notification for id: %s ", p.Options.ID))
		return err
	}

	for k, v := range p.Options.CustomHeaders {
		r.Header.Set(k, v)
	}

	_, err = httpreq.NewClient().Do(r)
	if err != nil {
		err = errors.Wrap(err, fmt.Sprintf("failed to send custom notification for id: %s ", p.Options.ID))
		return err
	}
	gologger.Verbose().Msgf("custom notification sent for id: %s", p.Options.ID)

	return nil
}
