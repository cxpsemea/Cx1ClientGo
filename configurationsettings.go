package Cx1ClientGo

import (
	"fmt"
	"strings"
)

// ConfigurationSettings provides an enum-like structure for various configuration keys.
var ConfigurationSettings = struct {
	SAST struct {
		BaseBranch            string
		EngineVerbose         string
		FastScanMode          string
		Filter                string
		Incremental           string
		LanguageMode          string
		LightQueries          string
		PresetName            string
		RecommendedExclusions string
		ScanMode              string
	}
	IAC struct {
		Filter    string
		Platforms string
		PresetID  string
	}
	SCA struct {
		ExploitablePath string
		Filter          string
		SBOM            string
	}
}{
	SAST: struct{ BaseBranch, EngineVerbose, FastScanMode, Filter, Incremental, LanguageMode, LightQueries, PresetName, RecommendedExclusions, ScanMode string }{"scan.config.sast.baseBranch", "scan.config.sast.engineVerbose", "scan.config.sast.fastScanMode", "scan.config.sast.filter", "scan.config.sast.incremental", "scan.config.sast.languageMode", "scan.config.sast.lightQueries", "scan.config.sast.presetName", "scan.config.sast.recommendedExclusions", "scan.config.sast.scanMode"},
	IAC:  struct{ Filter, Platforms, PresetID string }{"scan.config.kics.filter", "scan.config.kics.platforms", "scan.config.kics.presetId"},
	SCA:  struct{ ExploitablePath, Filter, SBOM string }{"scan.config.sca.ExploitablePath", "scan.config.sca.filter", "scan.config.sca.sbom"},
	//GIT:  struct{ Branch, Repository, SkipSubModules, SSHKey, Token string }{"scan.handler.git.branch", "scan.handler.git.repository", "scan.handler.git.skipSubModules", "scan.handler.git.sshKey", "scan.handler.git.token"},
}

// the ByName version of this function will be deprecated in favor of the correctly-named ByKey version
func (c *Cx1Client) GetConfigurationByName(config *[]ConfigurationSetting, configKey string) *ConfigurationSetting {
	c.depwarn("GetConfigurationByName", "GetConfigurationByKey")
	return getConfigurationByKey(config, configKey)
}

// Get the configuration for a specific key from a list of configuration settings
// You can fetch the list of settings via Get(Tenant/Project/Scan)Configuration functions
func (c *Cx1Client) GetConfigurationByKey(config *[]ConfigurationSetting, configKey string) *ConfigurationSetting {
	return getConfigurationByKey(config, configKey)
}

func getConfigurationByKey(config *[]ConfigurationSetting, configKey string) *ConfigurationSetting {
	for id := range *config {
		if (*config)[id].Key == configKey || (*config)[id].Name == configKey {
			return &((*config)[id])
		}
	}
	return nil
}

// Add a scan engine to a configuration set.
// This is only required if you don't want to set specific configs via AddConfig
func (s *ScanConfigurationSet) AddScanEngine(engine string) {
	switch engine {
	case "iac":
		engine = "kics"
	case "2ms", "secrets":
		s.AddConfig("microengines", "2ms", "true")
		return
	}
	newconf := ScanConfiguration{
		ScanType: engine,
		Values:   map[string]string{},
	}
	s.Configurations = append(s.Configurations, newconf)
}

// Add a specific key-value configuration for a scan, for example "sast", "incremental", "true"
// You can find the full list of key-value pairs via Swagger or Get*Configuration calls
func (s *ScanConfigurationSet) AddConfig(engine, key, value string) {
	switch engine {
	case "iac":
		engine = "kics"
	case "2ms", "secrets":
		s.AddConfig("microengines", "2ms", "true")
		return
	}

	for i := range s.Configurations {
		if s.Configurations[i].ScanType == engine {
			if key != "" {
				s.Configurations[i].Values[key] = value
			}
			return
		}
	}
	newconf := ScanConfiguration{
		ScanType: engine,
		Values:   map[string]string{},
	}
	if key != "" {
		newconf.Values[key] = value
	}
	s.Configurations = append(s.Configurations, newconf)
}

// To be used with full key names - shortcuts are defined in Cx1ClientGo.ConfigurationSettings
// eg to set a scan to incremental: s.SetKey( Cx1ClientGo.ConfigurationSettings.SAST.Incremental, "true" )
// Consumed when starting a scan: cx1client.ScanProjectZipByID( projectId, repoUrl, branch, s.Configurations, tags )
func (s *ScanConfigurationSet) SetKey(key, value string) error {
	parts := strings.Split(key, ".")
	if len(parts) != 4 {
		return fmt.Errorf("invalid configuration key - should have 4 parts eg: scan.config.sast.incremental")
	}

	s.AddConfig(parts[2], parts[3], value)

	return nil
}

func (c ConfigurationSetting) String() string {
	value := c.Value
	if value == "" {
		value = "[UNSET]"
	}
	return fmt.Sprintf("%v - %v - %v = %v", c.OriginLevel, c.Category, c.Name, value)
}

func (c ConfigurationSetting) StringDetailed() string {
	value := c.Value
	if value == "" {
		value = "[UNSET]"
	}
	return fmt.Sprintf("%v - %v = %v [Override: %v, options: %v]", c.OriginLevel, c.Key, value, c.AllowOverride, c.ValueTypeParams)
}
