package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"secure_secrets/internal/store"
	"sync"
	"time"
)

var (
	guiVersion       = Version
	activeGUIToken   string
	guiTokenConsumed bool
	tokenMutex       sync.Mutex
)

var (
	guiTokens      = make(map[store.ProfileName]string)
	guiTokensMutex sync.Mutex
)

func getGUIToken(profile store.ProfileName) string {
	guiTokensMutex.Lock()
	defer guiTokensMutex.Unlock()
	return guiTokens[profile]
}

func setGUIToken(profile store.ProfileName, token string) {
	guiTokensMutex.Lock()
	defer guiTokensMutex.Unlock()
	guiTokens[profile] = token
}

func generateGUIToken() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("fallback_%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b)
}
