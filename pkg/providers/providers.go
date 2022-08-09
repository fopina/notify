package providers

import (
	"github.com/acarl005/stripansi"
	"github.com/pkg/errors"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/notify/pkg/providers/slack"
	"github.com/projectdiscovery/notify/pkg/types"
	"github.com/projectdiscovery/notify/pkg/utils"
	"go.uber.org/multierr"
)

// ProviderOptions is configuration for notify providers
type ProviderOptions map[string][]*types.RawOptions

// Provider is an interface implemented by providers
type Provider interface {
	Send(message, CliFormat string) error
}

type Client struct {
	providers []Provider
	options   *types.Options
}

func New(providerOptions *ProviderOptions, options *types.Options) (*Client, error) {

	client := &Client{options: options}

	for k, v := range *providerOptions {
		var opts func(*types.RawOptions) (Provider, error)
		if k == "slack" {
			opts = func(options *types.RawOptions) (Provider, error) { p, err := slack.NewWithRaw(options); return p, err }
		} else {
			continue
		}
		for _, v1 := range v {
			if len(options.IDs) == 0 || utils.Contains(options.IDs, v1.ID) {
				provider, err := opts(v1)
				if err != nil {
					return nil, errors.Wrap(err, "could not create slack provider client")
				}
				client.providers = append(client.providers, provider)
			}
		}
	}

	/*

		processOptions := func(singleProviderOptions []*types.CommonProviderOptions, providerName string, newFunc func(*types.CommonProviderOptions) (Provider, error)) error {
			for _, o := range singleProviderOptions {
				if len(options.IDs) == 0 || utils.Contains(options.IDs, o.ID) {
					provider, err := newFunc(o)
					if err != nil {
						return errors.Wrap(err, "could not create slack provider client")
					}
					client.providers = append(client.providers, provider)
				}
			}
			return nil
		}

		processOptions(providerOptions.Slack, "slack", slack.New)
		/*
			if providerOptions.Discord != nil && (len(options.Providers) == 0 || utils.Contains(options.Providers, "discord")) {

				provider, err := discord.New(providerOptions.Discord, options.IDs)
				if err != nil {
					return nil, errors.Wrap(err, "could not create discord provider client")
				}
				client.providers = append(client.providers, provider)
			}
			/*
				if providerOptions.Pushover != nil && (len(options.Providers) == 0 || utils.Contains(options.Providers, "pushover")) {

					provider, err := pushover.New(providerOptions.Pushover, options.IDs)
					if err != nil {
						return nil, errors.Wrap(err, "could not create pushover provider client")
					}
					client.providers = append(client.providers, provider)
				}
				if providerOptions.SMTP != nil && (len(options.Providers) == 0 || utils.Contains(options.Providers, "smtp")) {

					provider, err := smtp.New(providerOptions.SMTP, options.IDs)
					if err != nil {
						return nil, errors.Wrap(err, "could not create smtp provider client")
					}
					client.providers = append(client.providers, provider)
				}
				if providerOptions.Teams != nil && (len(options.Providers) == 0 || utils.Contains(options.Providers, "teams")) {

					provider, err := teams.New(providerOptions.Teams, options.IDs)
					if err != nil {
						return nil, errors.Wrap(err, "could not create teams provider client")
					}
					client.providers = append(client.providers, provider)
				}
				if providerOptions.Telegram != nil && (len(options.Providers) == 0 || utils.Contains(options.Providers, "telegram")) {

					provider, err := telegram.New(providerOptions.Telegram, options.IDs)
					if err != nil {
						return nil, errors.Wrap(err, "could not create telegram provider client")
					}
					client.providers = append(client.providers, provider)
				}

				if providerOptions.Custom != nil && (len(options.Providers) == 0 || utils.Contains(options.Providers, "custom")) {
					for _, o := range providerOptions.Custom {
						if len(options.IDs) == 0 || utils.Contains(options.IDs, o.ID) {
							provider, err := custom.New(o)
							if err != nil {
								return nil, errors.Wrap(err, "could not create custom provider client")
							}
							client.providers = append(client.providers, provider)
						}
					}
				}
	*/

	return client, nil
}

func (p *Client) Send(message string) error {

	// strip unsupported color control chars
	message = stripansi.Strip(message)

	for _, v := range p.providers {
		if err := v.Send(message, p.options.MessageFormat); err != nil {
			for _, v := range multierr.Errors(err) {
				gologger.Error().Msgf("%s", v)
			}
		}
	}

	return nil
}
