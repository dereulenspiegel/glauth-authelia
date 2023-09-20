package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseUserDb(t *testing.T) {
	userData := `
users:
  dereulenspiegel:
    displayname: Till
    email: till@example.com
    groups:
    - admin
    - paperless
    password: somehash
  felix:
    displayname: Felix
    email: felix@example.com
    groups:
    - files
    password: anotherPasswordHash
`
	autheliaDb, err := parseAutheliaUserDb([]byte(userData))
	require.NoError(t, err)
	require.NotNil(t, autheliaDb)
	assert.Len(t, autheliaDb.Users, 2)
	assert.Len(t, autheliaDb.Groups, 3)
}
