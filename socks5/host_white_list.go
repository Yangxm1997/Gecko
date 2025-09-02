package socks5

import (
	"strings"
	"sync"

	"github.com/yangxm/gecko/logger"
)

type hostWhiteList struct {
	hosts map[string]bool
	mutex sync.RWMutex
}

var (
	hostWhiteListInstance *hostWhiteList
	hostWhiteListOnce     sync.Once
)

func HostWhiteList() *hostWhiteList {
	hostWhiteListOnce.Do(func() {
		hostWhiteListInstance = &hostWhiteList{
			hosts: make(map[string]bool),
		}
		logger.Debug("CREATE HWL")
	})
	return hostWhiteListInstance
}

func (h *hostWhiteList) Load(hosts []string) {
	logger.Debug("LOAD HWL --- %v", hosts)
	h.mutex.Lock()
	defer h.mutex.Unlock()

	// 清空旧数据
	h.hosts = make(map[string]bool)

	// 添加新数据
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host != "" {
			h.hosts[host] = true
			logger.Debug("LOAD HWL --- %s", host)
		}
	}
}

func (h *hostWhiteList) Add(host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		logger.Error("+ HWL FAILED, EMPTY PARAM")
		return
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	if h.hosts[host] {
		logger.Warn("+ HWL FAILED, DUPLICATE %s", host)
		return
	}

	h.hosts[host] = true
	logger.Debug("+ HWL --- %s", host)
}

func (h *hostWhiteList) Remove(host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		logger.Error("- HWL FAILED, EMPTY PARAM")
		return
	}

	h.mutex.Lock()
	defer h.mutex.Unlock()

	if !h.hosts[host] {
		logger.Warn("- HWL FAILED, NOT FOUND %s", host)
		return
	}

	delete(h.hosts, host)
	logger.Debug("- HWL --- %s", host)
}

func (h *hostWhiteList) Contains(host string, checkSubDomain bool) bool {
	host = strings.TrimSpace(host)
	if host == "" {
		logger.Error("CHK HWL FAILED, EMPTY PARAM")
		return false
	}

	h.mutex.RLock()
	defer h.mutex.RUnlock()

	// 检查完整域名
	if h.hosts[host] {
		return true
	}

	// 检查子域名
	if checkSubDomain {
		parts := strings.Split(host, ".")
		for i := 1; i < len(parts)-1; i++ {
			subDomain := strings.Join(parts[i:], ".")
			if h.hosts[subDomain] {
				return true
			}
		}
	}
	return false
}

func (h *hostWhiteList) GetHosts() []string {
	h.mutex.RLock()
	defer h.mutex.RUnlock()

	hosts := make([]string, 0, len(h.hosts))
	for host := range h.hosts {
		hosts = append(hosts, host)
	}
	return hosts
}
