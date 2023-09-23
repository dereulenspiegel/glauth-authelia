package main

import (
	"context"
	"errors"
	"net"
	"os"
	"sync"

	"github.com/GeertJohan/yubigo"
	"github.com/fsnotify/fsnotify"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/glauth/glauth/v2/pkg/stats"
	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/algorithm/plaintext"
	"github.com/nmcclain/ldap"
	"github.com/rs/zerolog"
)

func NewAutheliaFileHandler(opts ...handler.Option) handler.Handler {
	var err error
	options := handler.NewOptions(opts...)
	log := options.Logger
	ctx, cancelFn := context.WithCancel(context.Background())
	cdecoder, err := crypt.NewDefaultDecoder()
	if err != nil {
		log.Error().Err(err).Msg("failed to initialise password decode")
		cancelFn()
		return nil
	}
	if err := plaintext.RegisterDecoderPlainText(cdecoder); err != nil {
		log.Error().Err(err).Msg("failed to register plaintext password decoder")
		cancelFn()
		return nil
	}
	b := &AutheliaFileBackend{
		autheliaUserDbPath: options.Backend.Database,
		backgroundCtx:      ctx,
		cancelFn:           cancelFn,
		log:                log,
		ldohelper:          options.LDAPHelper,
		options:            &options,
		lock:               &sync.Mutex{},
		cdecoder:           cdecoder,
	}
	b.loadFile()
	b.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		b.log.Error().Err(err).Msg("Failed to create file watcher")
		cancelFn()
		return nil
	}
	if err := b.watcher.Add(b.autheliaUserDbPath); err != nil {
		b.log.Error().Err(err).Str("path", b.autheliaUserDbPath).Msg("Failed to watch file")
		cancelFn()
		return nil
	}
	b.watch()

	return b
}

func (a *AutheliaFileBackend) watch() {
	go func() {
		for {
			select {
			case <-a.backgroundCtx.Done():
				a.log.Info().Msg("Stop watching authelia user db")
				return
			case event, ok := <-a.watcher.Events:
				if !ok {
					return
				}
				if event.Op == fsnotify.Write {
					a.log.Info().Msg("Got update event for authelia user db")
					a.loadFile()
				}
			case err, ok := <-a.watcher.Errors:
				if !ok {
					return
				}
				a.log.Error().Err(err).Msg("Error during file watching")
			}
		}
	}()
}

func (a *AutheliaFileBackend) loadFile() {
	// Try reading the file. Might fail as write might not be complete yet
	fileData, err := os.ReadFile(a.autheliaUserDbPath)
	if err != nil {
		a.log.Error().Err(err).Msg("Failed to read authelia user db")
		return
	}
	autheliaDb, err := parseAutheliaUserDb(fileData)
	if err != nil {
		a.log.Error().Err(err).Msg("failed to parse authelia user db")
		return
	}
	a.log.Info().Msg("Authelia user db updated")
	a.lock.Lock()
	defer a.lock.Unlock()
	a.userDb = autheliaDb
}

func (a *AutheliaFileBackend) Bind(bindDN, bindSimplePw string, conn net.Conn) (ldap.LDAPResultCode, error) {
	a.log.Debug().Str("bindDN", bindDN).Msg("Binding user")
	result, err := a.ldohelper.Bind(a, bindDN, bindSimplePw, conn)
	if err != nil {
		a.log.Error().Err(err).Str("bindDN", bindDN).Msg("Binding user failed")
	}
	a.log.Debug().Str("ldapResult", ldap.LDAPResultCodeMap[result]).Msg("Got result from bind helper")
	return result, err
}

func (a *AutheliaFileBackend) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	a.log.Debug().Str("bindDN", bindDN).Msg("Searching user")
	return a.ldohelper.Search(a, bindDN, searchReq, conn)
}

func (a *AutheliaFileBackend) Close(boundDN string, conn net.Conn) error {
	stats.Frontend.Add("closes", 1)
	return nil
}

func (a *AutheliaFileBackend) CloseHandler() error {
	a.log.Info().Msg("Shutting down authelia plugin")
	a.cancelFn()
	return a.watcher.Close()
}

func (a *AutheliaFileBackend) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	a.log.Debug().Str("function", "Add").Msg("Uninplemented function called")
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (a *AutheliaFileBackend) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	a.log.Debug().Str("function", "Modify").Msg("Uninplemented function called")
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (a *AutheliaFileBackend) Delete(boundDN, deleteDN string, conn net.Conn) (ldap.LDAPResultCode, error) {
	a.log.Debug().Str("function", "Delete").Msg("Uninplemented function called")
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (a *AutheliaFileBackend) FindUser(userName string, searchByUPN bool) (bool, config.User, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.log.Debug().Str("username", userName).Msg("Trying to find user")
	autheliaUser, exists := a.userDb.Users[userName]
	if !exists {
		a.log.Debug().Str("username", userName).Msg("User does not exist")
		return false, config.User{}, errorUserDoesNotExist
	}
	return true, autheliaUser.ToLdapUser(a), nil
}

func (a *AutheliaFileBackend) FindGroup(groupName string) (bool, config.Group, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	a.log.Debug().Str("groupname", groupName).Msg("Trying to find group")
	group, exists := a.userDb.Groups[groupName]
	if !exists {
		return false, config.Group{}, errorGroupDoesNotExist
	}
	return exists, *group, nil
}

func (a *AutheliaFileBackend) GetBackend() config.Backend {
	return a.options.Backend
}

func (a *AutheliaFileBackend) GetLog() *zerolog.Logger {
	return a.log
}

func (a *AutheliaFileBackend) GetCfg() *config.Config {
	return a.options.Config
}

func (a *AutheliaFileBackend) GetYubikeyAuth() *yubigo.YubiAuth {
	return a.options.YubiAuth
}

func (a *AutheliaFileBackend) FindPosixAccounts(hierarchy string) (entrylist []*ldap.Entry, err error) {
	a.log.Debug().Str("function", "FindPosixAccounts").Msg("Uninplemented function called")
	return nil, errors.New("not implemented")
}

func (a *AutheliaFileBackend) FindPosixGroups(hierarchy string) (entrylist []*ldap.Entry, err error) {
	a.log.Debug().Str("function", "FindPosixGroups").Msg("Uninplemented function called")
	return nil, errorNotImplemented
}
