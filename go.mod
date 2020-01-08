module crossplane-secrets-controller

go 1.12

require (
	cloud.google.com/go v0.50.0 // indirect
	cloud.google.com/go/bigquery v1.3.0 // indirect
	cloud.google.com/go/pubsub v1.1.0 // indirect
	cloud.google.com/go/storage v1.4.0 // indirect
	dmitri.shuralyov.com/gpu/mtl v0.0.0-20191203043605-d42048ed14fd // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/antihax/optional v1.0.0 // indirect
	github.com/argoproj/argo-cd v1.3.6
	github.com/argoproj/pkg v0.0.0-20191031223000-02a6aac40ac4 // indirect
	github.com/casbin/casbin v1.9.1 // indirect
	github.com/cespare/xxhash/v2 v2.1.1 // indirect
	github.com/coreos/bbolt v1.3.3 // indirect
	github.com/coreos/etcd v3.3.18+incompatible // indirect
	github.com/coreos/go-systemd v0.0.0-20191111152658-2d78030078ef // indirect
	github.com/creack/pty v1.1.9 // indirect
	github.com/crossplaneio/crossplane v0.6.0
	github.com/envoyproxy/go-control-plane v0.9.1 // indirect
	github.com/go-logr/logr v0.1.0
	github.com/gobuffalo/envy v1.8.1 // indirect
	github.com/gobuffalo/logger v1.0.3 // indirect
	github.com/gobuffalo/packr v1.30.1 // indirect
	github.com/gobuffalo/packr/v2 v2.7.1 // indirect
	github.com/gogo/protobuf v1.3.1 // indirect
	github.com/golang/groupcache v0.0.0-20191027212112-611e8accdfc9 // indirect
	github.com/google/pprof v0.0.0-20191218002539-d4f498aebedc // indirect
	github.com/gopherjs/gopherjs v0.0.0-20191106031601-ce3c9ade29de // indirect
	github.com/gorilla/websocket v1.4.1 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.1.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway v1.12.1 // indirect
	github.com/jstemmer/go-junit-report v0.9.1 // indirect
	github.com/julienschmidt/httprouter v1.3.0 // indirect
	github.com/karrick/godirwalk v1.10.12 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f // indirect
	github.com/onsi/ginkgo v1.10.1
	github.com/onsi/gomega v1.7.0
	github.com/patrickmn/go-cache v2.1.0+incompatible // indirect
	github.com/pelletier/go-toml v1.6.0 // indirect
	github.com/prometheus/client_golang v1.2.1 // indirect
	github.com/prometheus/client_model v0.0.0-20191202183732-d1d2010b5bee // indirect
	github.com/prometheus/procfs v0.0.8 // indirect
	github.com/robfig/cron v1.2.0 // indirect
	github.com/rogpeppe/go-internal v1.5.1 // indirect
	github.com/russross/blackfriday v2.0.0+incompatible // indirect
	github.com/smartystreets/assertions v1.0.1 // indirect
	github.com/spf13/cast v1.3.1 // indirect
	github.com/spf13/jwalterweatherman v1.1.0 // indirect
	github.com/spf13/viper v1.6.1 // indirect
	github.com/ugorji/go v1.1.7 // indirect
	go.etcd.io/bbolt v1.3.3 // indirect
	go.opencensus.io v0.22.2 // indirect
	go.uber.org/atomic v1.5.1 // indirect
	go.uber.org/multierr v1.4.0 // indirect
	go.uber.org/zap v1.13.0 // indirect
	golang.org/x/crypto v0.0.0-20191219195013-becbf705a915 // indirect
	golang.org/x/image v0.0.0-20191214001246-9130b4cfad52 // indirect
	golang.org/x/mobile v0.0.0-20191210151939-1a1fef82734d // indirect
	golang.org/x/net v0.0.0-20191209160850-c0dbc17a3553 // indirect
	golang.org/x/oauth2 v0.0.0-20191202225959-858c2ad4c8b6 // indirect
	golang.org/x/sys v0.0.0-20191219235734-af0d71d358ab // indirect
	golang.org/x/time v0.0.0-20191024005414-555d28b269f0 // indirect
	golang.org/x/tools v0.0.0-20191219230827-5e752206af05 // indirect
	golang.org/x/xerrors v0.0.0-20191204190536-9bdfabe68543 // indirect
	google.golang.org/api v0.15.0 // indirect
	google.golang.org/appengine v1.6.5 // indirect
	google.golang.org/genproto v0.0.0-20191216205247-b31c10ee225f // indirect
	google.golang.org/grpc v1.26.0 // indirect
	gopkg.in/src-d/go-git.v4 v4.13.1 // indirect
	gopkg.in/yaml.v2 v2.2.7 // indirect
	k8s.io/api v0.0.0-20190918155943-95b840bb6a1f
	k8s.io/apimachinery v0.0.0-20190913080033-27d36303b655
	k8s.io/client-go v0.0.0-20190918160344-1fbdaa4c8d90
	sigs.k8s.io/controller-runtime v0.4.0
)

replace golang.org/x/net => github.com/golang/net v0.0.0-20191209160850-c0dbc17a3553

replace github.com/coreos/go-systemd => github.com/coreos/go-systemd/v22 v22.0.0
