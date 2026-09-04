package main

import (
	"sync"
	"time"
)

var (
	activeTabID      string
	lastTabHeartbeat time.Time
	tabMutex         sync.Mutex
)
