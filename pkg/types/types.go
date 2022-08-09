package types

import "github.com/projectdiscovery/goflags"

type Options struct {
	Verbose        bool                          `yaml:"verbose,omitempty"`
	NoColor        bool                          `yaml:"no_color,omitempty"`
	Silent         bool                          `yaml:"silent,omitempty"`
	Version        bool                          `yaml:"version,omitempty"`
	ProviderConfig string                        `yaml:"provider_config,omitempty"`
	Providers      goflags.NormalizedStringSlice `yaml:"providers,omitempty"`
	IDs            goflags.NormalizedStringSlice `yaml:"ids,omitempty"`
	Proxy          string                        `yaml:"proxy,omitempty"`
	RateLimit      int                           `yaml:"rate_limit,omitempty"`

	MessageFormat string `yaml:"message_format,omitempty"`

	Stdin     bool
	Bulk      bool   `yaml:"bulk,omitempty"`
	CharLimit int    `yaml:"char_limit,omitempty"`
	Data      string `yaml:"data,omitempty"`
}

type RawOptions struct {
	unmarshal func(interface{}) error
}

func (options *RawOptions) UnmarshalYAML(unmarshal func(interface{}) error) error {
	options.unmarshal = unmarshal
	return nil
}

// call this method later - when we know what concrete type to use
func (options *RawOptions) Unmarshal(v interface{}) error {
	return options.unmarshal(v)
}
