package routeros

import "github.com/go-routeros/routeros/v3"

// Client - describes RouterOS command runner interface
type Client interface {
	Run(sentence ...string) (*routeros.Reply, error)
	Close() error
	Async() <-chan error
}
