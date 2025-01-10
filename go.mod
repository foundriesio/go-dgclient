module github.com/foundriesio/go-dgclient/v1

go 1.22

require (
	github.com/ThalesIgnite/crypto11 v1.2.5
	github.com/pelletier/go-toml v1.9.5
	github.com/stretchr/testify v1.10.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/miekg/pkcs11 v1.0.3-0.20190429190417-a667d056470f // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// We have really old devices that had invalid toml where string values weren't
// quoted. eg:
//   foo = bar
// This override pulls in a hack that can parse this
replace github.com/pelletier/go-toml => github.com/foundriesio/go-toml v1.8.1-0.20200721033514-2232fec316b9
