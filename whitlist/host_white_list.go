package whitlist

import (
	"github.com/yangxm/gecko/logger"
	"strings"
)

var whitelist = make(map[string]bool)

func Load(hosts []string) {
	logger.Debug("LOAD HWL --- %v", hosts)
	// 清空旧数据
	whitelist = make(map[string]bool)

	// 添加新数据
	for _, host := range hosts {
		host = strings.TrimSpace(host)
		if host != "" {
			whitelist[host] = true
			logger.Debug("LOAD HWL --- %s", host)
		}
	}
}

func Add(host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		logger.Error("+ HWL FAILED, EMPTY PARAM")
		return
	}

	if whitelist[host] {
		logger.Warn("+ HWL FAILED, DUPLICATE %s", host)
		return
	}

	whitelist[host] = true
	logger.Debug("+ HWL --- %s", host)
}

func Remove(host string) {
	host = strings.TrimSpace(host)
	if host == "" {
		logger.Error("- HWL FAILED, EMPTY PARAM")
		return
	}

	if !whitelist[host] {
		logger.Warn("- HWL FAILED, NOT FOUND %s", host)
		return
	}

	delete(whitelist, host)
	logger.Debug("- HWL --- %s", host)
}

func Contains(host string, checkSubDomain bool) bool {
	//return true
	host = strings.TrimSpace(host)
	if host == "" {
		logger.Error("CHK HWL FAILED, EMPTY PARAM")
		return false
	}

	// 检查完整域名
	if whitelist[host] {
		return true
	}

	// 检查子域名
	if checkSubDomain {
		parts := strings.Split(host, ".")
		for i := 1; i < len(parts)-1; i++ {
			subDomain := strings.Join(parts[i:], ".")
			if whitelist[subDomain] {
				return true
			}
		}
	}
	return false
}

func GetHosts() []string {
	hosts := make([]string, 0, len(whitelist))
	for host := range whitelist {
		hosts = append(hosts, host)
	}
	return hosts
}
