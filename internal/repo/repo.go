package repo

import (
	"fmt"
	"io/ioutil"
	"path/filepath"

	libp2pcert "github.com/meshplus/go-libp2p-cert"
)

type Repo struct {
	Config        *Config
	NetworkConfig *NetworkConfig
	Key           *Key
	Certs         *libp2pcert.Certs
}

func Load(repoRoot string, passwd string, configPath, networkPath string) (*Repo, error) {
	config, err := UnmarshalConfig(repoRoot, configPath)
	if err != nil {
		return nil, err
	}

	var networkConfig *NetworkConfig
	if len(networkPath) == 0 {
		networkConfig, err = loadNetworkConfig(repoRoot, config.Genesis)
	} else {
		networkConfig, err = loadNetworkConfig(filepath.Dir(networkPath), config.Genesis)
		fileData, err := ioutil.ReadFile(networkPath)
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(filepath.Join(repoRoot, "network.toml"), fileData, 0644)
		if err != nil {
			return nil, err
		}
	}
	if err != nil {
		return nil, fmt.Errorf("load network config: %w", err)
	}

	certs, err := libp2pcert.LoadCerts(repoRoot, config.NodeCertPath, config.AgencyCertPath, config.CACertPath)
	if err != nil {
		return nil, err
	}

	key, err := loadPrivKey(repoRoot, passwd)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	return &Repo{
		Config:        config,
		NetworkConfig: networkConfig,
		Key:           key,
		Certs:         certs,
	}, nil
}

func GetAPI(repoRoot string) (string, error) {
	data, err := ioutil.ReadFile(filepath.Join(repoRoot, APIName))
	if err != nil {
		return "", err
	}

	return string(data), nil
}

func GetKeyPath(repoRoot string) string {
	return filepath.Join(repoRoot, KeyName)
}

func GetStoragePath(repoRoot string, subPath ...string) string {
	p := filepath.Join(repoRoot, "storage")
	for _, s := range subPath {
		p = filepath.Join(p, s)
	}

	return p
}
