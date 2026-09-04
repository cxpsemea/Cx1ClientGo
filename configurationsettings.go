package Cx1ClientGo

import (
	"fmt"
	"strings"
)

type scanConfigSettingsSAST struct {
	BaseBranch            string
	EngineVerbose         string // "true" or "false"
	FastScanMode          string // "true" or "false"
	Filter                string
	Incremental           string // "true" or "false"
	LanguageMode          string // "primary" or "multi"
	LightQueries          string // "true" or "false"
	PresetName            string
	RecommendedExclusions string // "true" or "false"
}

var scanConfigsSAST = scanConfigSettingsSAST{
	BaseBranch:            "scan.config.sast.baseBranch",
	EngineVerbose:         "scan.config.sast.engineVerbose",
	FastScanMode:          "scan.config.sast.fastScanMode",
	Filter:                "scan.config.sast.filter",
	Incremental:           "scan.config.sast.incremental",
	LanguageMode:          "scan.config.sast.languageMode",
	LightQueries:          "scan.config.sast.lightQueries",
	PresetName:            "scan.config.sast.presetName",
	RecommendedExclusions: "scan.config.sast.recommendedExclusions",
}

type scanConfigSettingsIAC struct {
	Filter    string
	Platforms string
	PresetID  string
}

var scanConfigsIAC = scanConfigSettingsIAC{
	Filter:    "scan.config.kics.filter",
	Platforms: "scan.config.kics.platforms",
	PresetID:  "scan.config.kics.presetId",
}

type scanConfigSettingsSCA struct {
	ExploitablePath string
	Filter          string
	SBOM            string
}

var scanConfigsSCA = scanConfigSettingsSCA{
	ExploitablePath: "scan.config.sca.ExploitablePath",
	Filter:          "scan.config.sca.filter",
	SBOM:            "scan.config.sca.sbom",
}

// ConfigurationSettings provides an enum-like structure for various configuration keys.
var ConfigurationSettings = struct {
	SAST    scanConfigSettingsSAST
	IAC     scanConfigSettingsIAC
	SCA     scanConfigSettingsSCA
	Engines struct {
		AISupplyChain, APISecurity, Containers, IAC, SAST, SCA, Secrets string
	}
}{
	SAST:    scanConfigsSAST,
	IAC:     scanConfigsIAC,
	SCA:     scanConfigsSCA,
	Engines: struct{ AISupplyChain, APISecurity, Containers, IAC, SAST, SCA, Secrets string }{"aisc", "apisec", "containers", "kics", "sast", "sca", "microengines"},
	//GIT:  struct{ Branch, Repository, SkipSubModules, SSHKey, Token string }{"scan.handler.git.branch", "scan.handler.git.repository", "scan.handler.git.skipSubModules", "scan.handler.git.sshKey", "scan.handler.git.token"},
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
	case "2ms", "secrets", "microengines":
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

func NewScanConfiguration() *ScanConfigurationSet {
	return &ScanConfigurationSet{}
}

// convenience function to add AI Supply Chain engine, returns pointer to self for chaining
func (s *ScanConfigurationSet) WithAISC() *ScanConfigurationSet {
	s.AddScanEngine("aisc")
	return s
}

// convenience function to add APISEC engine, returns pointer to self for chaining
func (s *ScanConfigurationSet) WithAPISEC() *ScanConfigurationSet {
	s.AddScanEngine("apisec")
	return s
}

// convenience function to add Containers engine, returns pointer to self for chaining
func (s *ScanConfigurationSet) WithContainers() *ScanConfigurationSet {
	s.AddScanEngine("containers")
	return s
}

// convenience function to add IAC/KICS engine, returns pointer to self for chaining
func (s *ScanConfigurationSet) WithIAC() *ScanConfigurationSet {
	s.AddScanEngine("kics")
	return s
}

// convenience function to set IAC engine keys, returns pointer to self for chaining
// configuration keys are available via Cx1ClientGo.ConfigurationSettings
func (s *ScanConfigurationSet) WithIACConfig(key, value string) *ScanConfigurationSet {
	s.AddConfig(ConfigurationSettings.Engines.IAC, key, value)
	return s
}

// convenience function to add SAST engine, returns pointer to self for chaining
func (s *ScanConfigurationSet) WithSAST() *ScanConfigurationSet {
	s.AddScanEngine("sast")
	return s
}

// convenience function to set SAST engine keys, returns pointer to self for chaining
// configuration keys are available via Cx1ClientGo.ConfigurationSettings
func (s *ScanConfigurationSet) WithSASTConfig(key, value string) *ScanConfigurationSet {
	s.AddConfig(ConfigurationSettings.Engines.SAST, key, value)
	return s
}

// convenience function to add SCA engine, returns pointer to self for chaining
func (s *ScanConfigurationSet) WithSCA() *ScanConfigurationSet {
	s.AddScanEngine("sca")
	return s
}

// convenience function to set SCA engine keys, returns pointer to self for chaining
// configuration keys are available via Cx1ClientGo.ConfigurationSettings
func (s *ScanConfigurationSet) WithSCAConfig(key, value string) *ScanConfigurationSet {
	s.AddConfig(ConfigurationSettings.Engines.SCA, key, value)
	return s
}

// convenience function to add Secrets/2ms engine, returns pointer to self for chaining
func (s *ScanConfigurationSet) WithSecrets() *ScanConfigurationSet {
	s.AddConfig("microengines", "2ms", "true")
	return s
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
