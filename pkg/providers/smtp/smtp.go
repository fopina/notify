package smtp

import (
	"fmt"
	"strings"

	"github.com/containrrr/shoutrrr"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/notify/pkg/utils"
)

type Provider struct {
	Options *Options `yaml:"smtp,omitempty"`
}

type Options struct {
	ID          string   `yaml:"id,omitempty"`
	Server      string   `yaml:"smtp_server,omitempty"`
	Username    string   `yaml:"smtp_username,omitempty"`
	Password    string   `yaml:"smtp_password,omitempty"`
	FromAddress string   `yaml:"from_address,omitempty"`
	SMTPCC      []string `yaml:"smtp_cc,omitempty"`
	SMTPFormat  string   `yaml:"smtp_format,omitempty"`
	Subject     string   `yaml:"subject,omitempty"`
}

func New(options *Options) (*Provider, error) {
	provider := &Provider{Options: options}
	return provider, nil
}

func (p *Provider) Send(message, CliFormat string) error {
	msg := utils.FormatMessage(message, utils.SelectFormat(CliFormat, p.Options.SMTPFormat))

	url := fmt.Sprintf("smtp://%s:%s@%s/?fromAddress=%s&toAddresses=%s&subject=%s", p.Options.Username, p.Options.Password, p.Options.Server, p.Options.FromAddress, strings.Join(p.Options.SMTPCC, ","), p.Options.Subject)
	err := shoutrrr.Send(url, msg)
	if err != nil {
		return errors.Wrap(err, fmt.Sprintf("failed to send smtp notification for id: %s ", p.Options.ID))
	}
	gologger.Verbose().Msgf("smtp notification sent for id: %s", p.Options.ID)
	return nil
}
