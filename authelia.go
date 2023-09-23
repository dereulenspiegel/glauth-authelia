package main

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/fsnotify/fsnotify"
	"github.com/glauth/glauth/v2/pkg/config"
	"github.com/glauth/glauth/v2/pkg/handler"
	"github.com/go-crypt/crypt"
	"github.com/rs/zerolog"
	"gopkg.in/yaml.v3"
)

var (
	errorUserDoesNotExist  = errors.New("user does not exist")
	errorInvalidPassword   = errors.New("invalid password")
	errorNotImplemented    = errors.New("not implemented")
	errorGroupDoesNotExist = errors.New("group does not exist")
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
	cdecoder      *crypt.Decoder
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

func parseAutheliaUserDb(fileBytes []byte) (*AutheliaUserDb, error) {
	var autheliaDb AutheliaUserDb
	autheliaDb.Groups = make(map[string]*config.Group)
	autheliaDb.Users = make(map[string]*User)
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

func (a *AutheliaFileBackend) MatchPassword(user *config.User, pw string) error {
	autheliaUser, exists := a.userDb.Users[user.Name]
	if !exists {
		return errorUserDoesNotExist
	}

	digest, err := a.cdecoder.Decode(autheliaUser.Password)
	if err != nil {
		return fmt.Errorf("failed to decode password string: %w", err)
	}
	matching, err := digest.MatchAdvanced(pw)
	if err != nil {
		return fmt.Errorf("failed to match digest: %w", err)
	}
	if !matching {
		return errorInvalidPassword
	}
	return nil
}
