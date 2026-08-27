module github.com/g0lab/g0efilter/agent

go 1.27.0

require (
	github.com/florianl/go-nflog/v2 v2.3.0
	github.com/g0lab/g0efilter/shared v0.0.0
	github.com/google/gopacket v1.1.19
	github.com/miekg/dns v1.1.73
	github.com/nicholas-fedor/shoutrrr v0.17.2
	github.com/rs/zerolog v1.35.1
	go.yaml.in/yaml/v4 v4.0.0-rc.6
	golang.org/x/crypto v0.55.0
	golang.org/x/net v0.58.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/eclipse/paho.golang v0.23.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/mattn/go-colorable v0.1.15 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mdlayher/netlink v1.9.1-0.20260312172110-2a932c0fc1ae // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	golang.org/x/sync v0.22.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
)

replace github.com/g0lab/g0efilter/shared => ../shared
