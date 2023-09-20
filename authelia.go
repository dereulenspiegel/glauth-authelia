package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/GeertJohan/yubigo"
	"github.com/fsnotify/fsnotify"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/go-crypt/crypt"
	"github.com/go-crypt/crypt/algorithm/plaintext"
	"github.com/nmcclain/ldap"
	"github.com/rs/zerolog"
	yaml "gopkg.in/yaml.v3"
)

const (
	groupIdBase = 10000
)

type AutheliaFileBackend struct {
	autheliaUserDbPath string
	watcher            *fsnotify.Watcher
	log                *zerolog.Logger

	lock          *sync.Mutex
	backgroundCtx context.Context
	cancelFn      context.CancelFunc
	userDb        *AutheliaUserDb
	ldohelper     handler.LDAPOpsHelper
	options       *handler.Options
}

type AutheliaUserDb struct {
	Users  map[string]*User
	Groups map[string]*config.Group
}

type User struct {
	Username     string
	Displayname  string
	Email        string
	Password     string
	Groups       []string
	PrimaryGroup *config.Group
}

func (u *User) ToLdapUser(a *AutheliaFileBackend) config.User {
	return config.User{
		Name:          u.Username,
		Disabled:      false,
		Mail:          u.Email,
		LoginShell:    "/usr/bin/false",
		GivenName:     u.Displayname,
		PrimaryGroup:  u.PrimaryGroup.GIDNumber,
		PassAppCustom: a.MatchPassword,
		// UIDNumber: 0, We try to ignore this for now
	}
}

func NewAutheliaFileHandler(opts ...handler.Option) handler.Handler {
	var err error
	options := handler.NewOptions(opts...)
	ctx, cancelFn := context.WithCancel(context.Background())
	b := &AutheliaFileBackend{
		autheliaUserDbPath: options.Backend.Datastore,
		backgroundCtx:      ctx,
		cancelFn:           cancelFn,
		log:                options.Logger,
		ldohelper:          options.LDAPHelper,
		options:            &options,
	}

	b.watcher, err = fsnotify.NewWatcher()
	if err != nil {
		b.log.Error().Err(err).Msg("Failed to create file watcher")
	}
	if err := b.watcher.Add(options.Backend.Datastore); err != nil {
		b.log.Error().Err(err).Str("path", options.Backend.Datastore).Msg("Failed to watch file")
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
	return a.ldohelper.Bind(a, bindDN, bindSimplePw, conn)
}

func (a *AutheliaFileBackend) Search(bindDN string, searchReq ldap.SearchRequest, conn net.Conn) (ldap.ServerSearchResult, error) {
	return a.ldohelper.Search(a, bindDN, searchReq, conn)
}

func (a *AutheliaFileBackend) Close(boundDN string, conn net.Conn) error {
	a.cancelFn()
	return a.watcher.Close()
}

func (a *AutheliaFileBackend) Add(boundDN string, req ldap.AddRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (a *AutheliaFileBackend) Modify(boundDN string, req ldap.ModifyRequest, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (a *AutheliaFileBackend) Delete(boundDN, deleteDN string, conn net.Conn) (ldap.LDAPResultCode, error) {
	return ldap.LDAPResultInsufficientAccessRights, nil
}

func (a *AutheliaFileBackend) FindUser(userName string, searchByUPN bool) (bool, config.User, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	autheliaUser, exists := a.userDb.Users[userName]
	if !exists {
		return false, config.User{}, errors.New("user not found")
	}
	return true, autheliaUser.ToLdapUser(a), nil
}

func (a *AutheliaFileBackend) FindGroup(groupName string) (bool, config.Group, error) {
	a.lock.Lock()
	defer a.lock.Unlock()
	group, exists := a.userDb.Groups[groupName]
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
	return nil, errors.New("not implemented")
}

func (a *AutheliaFileBackend) FindPosixGroups(hierarchy string) (entrylist []*ldap.Entry, err error) {
	return nil, errors.New("not implemented")
}

func (a *AutheliaFileBackend) MatchPassword(user *config.User, pw string) error {
	autheliaUser, exists := a.userDb.Users[user.Name]
	if !exists {
		return errors.New("user does not exist")
	}
	cdecoder, err := crypt.NewDefaultDecoder()
	if err != nil {
		return err
	}
	if err := plaintext.RegisterDecoderPlainText(cdecoder); err != nil {
		return nil
	}
	digest, err := cdecoder.Decode(autheliaUser.Password)
	if err != nil {
		return err
	}
	matching, err := digest.MatchAdvanced(pw)
	if err != nil {
		return err
	}
	if !matching {
		return errors.New("invalid password")
	}
	return nil
}

func parseAutheliaUserDb(fileBytes []byte) (*AutheliaUserDb, error) {
	var autheliaDb AutheliaUserDb
	if err := yaml.Unmarshal(fileBytes, &autheliaDb); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authelia user db yaml: %s", err)
	}
	autheliaDb.Groups = make(map[string]*config.Group)
	groupIdCounter := groupIdBase
	for username, user := range autheliaDb.Users {
		user.Username = username
		firstGroup := true
		for _, groupName := range user.Groups {
			var group *config.Group
			var exists bool
			if group, exists = autheliaDb.Groups[groupName]; !exists {
				group = &config.Group{
					Name:      groupName,
					GIDNumber: groupIdCounter, // Thats very primitive but might work...
				}
				autheliaDb.Groups[groupName] = group
				groupIdCounter = groupIdCounter + 1
			}

			if firstGroup {
				// Simply use the first found group as the users primary group
				user.PrimaryGroup = group
				firstGroup = false
			}
		}
	}
	return &autheliaDb, nil
}
