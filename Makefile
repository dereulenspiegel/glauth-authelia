# Note: to make a plugin compatible with a binary built in debug mode, add `-gcflags='all=-N -l'`

PLUGIN_OS ?= linux
PLUGIN_ARCH ?= amd64

plugin_authelia: bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/authelia.so

bin/$(PLUGIN_OS)$(PLUGIN_ARCH)/authelia.so: pkg/plugins/glauth-authelia/authelia.go
	GOOS=$(PLUGIN_OS) GOARCH=$(PLUGIN_ARCH) go build ${TRIM_FLAGS} -ldflags "${BUILD_VARS}" -buildmode=plugin -o $@ $^

plugin_authelia_linux_amd64:
	PLUGIN_OS=linux PLUGIN_ARCH=amd64 make plugin_authelia

plugin_authelia_linux_arm64:
	PLUGIN_OS=linux PLUGIN_ARCH=arm64 make plugin_authelia

plugin_authelia_darwin_amd64:
	PLUGIN_OS=darwin PLUGIN_ARCH=amd64 make plugin_authelia

plugin_authelia_darwin_arm64:
	PLUGIN_OS=darwin PLUGIN_ARCH=arm64 make plugin_authelia

release-glauth-authelia:
	@P=authelia M=pkg/plugins/glauth-authelia make releaseplugin