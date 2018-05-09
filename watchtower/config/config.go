package config

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	flags "github.com/btcsuite/go-flags"
	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/roasbeef/btcd/btcec"
	"github.com/roasbeef/btcd/chaincfg"
	"github.com/roasbeef/btcutil"
)

// Name watchtower F: wtf?
const (
	DefaultServerPort     = 9777
	defaultConfigFilename = "watchtower.conf"
	defaultDataDirname    = "data"
	defaultLogLevel       = "info"
	defaultLogDirname     = "logs"
	defaultLogFilename    = "watchtower.log"
	defaultRPCPort        = 10009
	defaultRESTPort       = 8080
	defaultPeerPort       = 9735
)

var (
	// TODO(roasbeef): base off of datadir instead?
	wtHomeDir         = btcutil.AppDataDir("watchtower", false)
	defaultConfigFile = filepath.Join(wtHomeDir, defaultConfigFilename)
	defaultDataDir    = filepath.Join(wtHomeDir, defaultDataDirname)
	defaultLogDir     = filepath.Join(wtHomeDir, defaultLogDirname)

	activeNetParams = &chaincfg.MainNetParams
)

var serverPrivKey = "cabe4ab4b376fed2802423086135c7151fba977b9485b900c569520a40796d4f"
var serverPrivKeyBytes, _ = hex.DecodeString(serverPrivKey)
var ServerPrivKey, _ = btcec.PrivKeyFromBytes(btcec.S256(), serverPrivKeyBytes)

type ChainConfig struct {
	Active   bool   `long:"active" description:"If the chain should be active or not."`
	ChainDir string `long:"chaindir" description:"The directory to store the chains's data within."`

	TestNet3 bool `long:"testnet" description:"Use the test network"`
	SimNet   bool `long:"simnet" description:"Use the simulation test network"`
	RegTest  bool `long:"regtest" description:"Use the regression test network"`

	Params *chaincfg.Params
}

type NeutrinoConfig struct {
	Active       bool          `long:"active" description:"If SPV mode should be active or not."`
	AddPeers     []string      `short:"a" long:"addpeer" description:"Add a peer to connect with at startup"`
	ConnectPeers []string      `long:"connect" description:"Connect only to the specified peers at startup"`
	MaxPeers     int           `long:"maxpeers" description:"Max number of inbound and outbound peers"`
	BanDuration  time.Duration `long:"banduration" description:"How long to ban misbehaving peers.  Valid time units are {s, m, h}.  Minimum 1 second"`
	BanThreshold uint32        `long:"banthreshold" description:"Maximum allowed ban score before disconnecting and banning misbehaving peers."`
}

type Config struct {
	ShowVersion bool `short:"V" long:"version" description:"Display version information and exit"`

	ConfigFile string `long:"C" long:"configfile" description:"Path to configuration file"`
	DataDir    string `short:"b" long:"datadir" description:"The directory to store lnd's data within"`
	LogDir     string `long:"logdir" description:"Directory to log output."`

	Listeners []string `long:"listen" description:"Add an interface/port to listen for connections (default all interfaces port: 9735)"`

	DebugLevel string `short:"d" long:"debuglevel" description:"Logging level for all subsystems {trace, debug, info, warn, error, critical} -- You may also specify <subsystem>=<level>,<subsystem2>=<level>,... to set the log level for individual subsystems -- Use show to list available subsystems"`

	CPUProfile string `long:"cpuprofile" description:"Write CPU profile to the specified file"`

	Profile string `long:"profile" description:"Enable HTTP profiling on given port -- NOTE port must be between 1024 and 65536"`

	PeerPort int `long:"peerport" description:"The port to listen on for incoming p2p connections"`
	RPCPort  int `long:"rpcport" description:"The port for the rpc server"`
	RESTPort int `long:"restport" description:"The port for the REST server"`

	Litecoin *ChainConfig `group:"Litecoin" namespace:"litecoin"`
	Bitcoin  *ChainConfig `group:"Bitcoin" namespace:"bitcoin"`

	RewardAddress string `long:"address" description:"Address to send any funds awarded from detecting breaches."`

	NeutrinoMode *NeutrinoConfig `group:"neutrino" namespace:"neutrino"`
}

// loadConfig initializes and parses the config using a config file and command
// line options.
//
// The configuration proceeds as follows:
// 	1) Start with a default config with sane settings
// 	2) Pre-parse the command line to check for an alternative config file
// 	3) Load configuration file overwriting defaults with any specified options
// 	4) Parse CLI options and overwrite/add any specified options
func LoadConfig() (*Config, error) {

	defaultCfg := Config{
		ConfigFile: defaultConfigFile,
		DataDir:    defaultDataDir,
		DebugLevel: defaultLogLevel,
		LogDir:     defaultLogDir,
		PeerPort:   defaultPeerPort,
		RPCPort:    defaultRPCPort,
		RESTPort:   defaultRESTPort,
		Bitcoin:    &ChainConfig{},
		Litecoin:   &ChainConfig{},
	}
	// Pre-parse the command line options to pick up an alternative config
	// file.
	preCfg := defaultCfg
	if _, err := flags.Parse(&preCfg); err != nil {
		return nil, err
	}

	// Show the version and exit if the version flag was specified.
	appName := filepath.Base(os.Args[0])
	appName = strings.TrimSuffix(appName, filepath.Ext(appName))
	usageMessage := fmt.Sprintf("Use %s -h to show usage", appName)
	if preCfg.ShowVersion {
		fmt.Println(appName, "version", "lol")
		os.Exit(0)
	}

	// Create the home directory if it doesn't already exist.
	funcName := "loadConfig"
	if err := os.MkdirAll(wtHomeDir, 0700); err != nil {
		// Show a nicer error message if it's because a symlink is
		// linked to a directory that does not exist (probably because
		// it's not mounted).
		if e, ok := err.(*os.PathError); ok && os.IsExist(err) {
			if link, lerr := os.Readlink(e.Path); lerr == nil {
				str := "is symlink %s -> %s mounted?"
				err = fmt.Errorf(str, e.Path, link)
			}
		}

		str := "%s: Failed to create home directory: %v"
		err := fmt.Errorf(str, funcName, err)
		fmt.Fprintln(os.Stderr, err)
		return nil, err
	}

	// Next, load any additional configuration options from the file.
	var configFileError error
	cfg := defaultCfg
	if err := flags.IniParse(preCfg.ConfigFile, &cfg); err != nil {
		configFileError = err
	}

	// Finally, parse the remaining command line options again to ensure
	// they take precedence.
	if _, err := flags.Parse(&cfg); err != nil {
		return nil, err
	}

	// At this moment, multiple active chains are not supported.
	if cfg.Litecoin.Active && cfg.Bitcoin.Active {
		str := "%s: Currently both Bitcoin and Litecoin cannot be " +
			"active together"
		err := fmt.Errorf(str, funcName)
		return nil, err
	}

	switch {
	// The SPV mode implemented currently doesn't support Litecoin, so the
	// two modes are incompatible.
	case cfg.Litecoin.Active:
		str := "%s: The light client mode currently supported does " +
			"not yet support execution on the Litecoin network"
		err := fmt.Errorf(str, funcName)
		return nil, err

	// Either Bitcoin must be active, or Litecoin must be active.
	// Otherwise, we don't know which chain we're on.
	case !cfg.Bitcoin.Active && !cfg.Litecoin.Active:
		return nil, fmt.Errorf("either bitcoin.active or " +
			"litecoin.active must be set to 1 (true)")

	case cfg.Bitcoin.Active:
		// Multiple networks can't be selected simultaneously.  Count
		// number of network flags passed; assign active network params
		// while we're at it.
		numNets := 0
		if cfg.Bitcoin.TestNet3 {
			numNets++
			activeNetParams = &chaincfg.TestNet3Params
			cfg.Bitcoin.Params = &chaincfg.TestNet3Params
		}
		if cfg.Bitcoin.RegTest {
			numNets++
			activeNetParams = &chaincfg.RegressionNetParams
			cfg.Bitcoin.Params = &chaincfg.RegressionNetParams
		}
		if cfg.Bitcoin.SimNet {
			numNets++
			activeNetParams = &chaincfg.SimNetParams
			cfg.Bitcoin.Params = &chaincfg.SimNetParams
		}
		if numNets > 1 {
			str := "%s: The testnet, segnet, and simnet params can't be " +
				"used together -- choose one of the three"
			err := fmt.Errorf(str, funcName)
			return nil, err
		}
		cfg.Bitcoin.ChainDir = filepath.Join(cfg.DataDir, "bitcoin")
	}

	// Validate profile port number.
	if cfg.Profile != "" {
		profilePort, err := strconv.Atoi(cfg.Profile)
		if err != nil || profilePort < 1024 || profilePort > 65535 {
			str := "%s: The profile port must be between 1024 and 65535"
			err := fmt.Errorf(str, funcName)
			fmt.Fprintln(os.Stderr, err)
			fmt.Fprintln(os.Stderr, usageMessage)
			return nil, err
		}
	}

	// Append the network type to the data directory so it is "namespaced"
	// per network. In addition to the block database, there are other
	// pieces of data that are saved to disk such as address manager state.
	// All data is specific to a network, so namespacing the data directory
	// means each individual piece of serialized data does not have to
	// worry about changing names per network and such.
	cfg.DataDir = cleanAndExpandPath(cfg.DataDir)
	cfg.DataDir = filepath.Join(cfg.DataDir, "bitcoin")
	cfg.DataDir = filepath.Join(cfg.DataDir, activeNetParams.Name)

	// Append the network type to the log directory so it is "namespaced"
	// per network in the same fashion as the data directory.
	cfg.LogDir = cleanAndExpandPath(cfg.LogDir)
	cfg.LogDir = filepath.Join(cfg.LogDir, "bitcoin")
	cfg.LogDir = filepath.Join(cfg.LogDir, activeNetParams.Name)

	// Warn about missing config file only after all other configuration is
	// done.  This prevents the warning on help messages and invalid
	// options.  Note this should go directly before the return.
	if configFileError != nil {
		fmt.Printf("%v", configFileError)
	}

	return &cfg, nil
}

// cleanAndExpandPath expands environment variables and leading ~ in the
// passed path, cleans the result, and returns it.
// This function is taken from https://github.com/btcsuite/btcd
func cleanAndExpandPath(path string) string {
	// Expand initial ~ to OS specific home directory.
	if strings.HasPrefix(path, "~") {
		homeDir := filepath.Dir(wtHomeDir)
		path = strings.Replace(path, "~", homeDir, 1)
	}

	// NOTE: The os.ExpandEnv doesn't work with Windows-style %VARIABLE%,
	// but the variables can still be expanded via POSIX-style $VARIABLE.
	return filepath.Clean(os.ExpandEnv(path))
}

// NoiseDial is a factory function which creates a connmgr compliant dialing
// function by returning a closure which includes the server's identity key.
func NoiseDial(idPriv *btcec.PrivateKey) func(net.Addr) (net.Conn, error) {
	return func(a net.Addr) (net.Conn, error) {
		lnAddr := a.(*lnwire.NetAddress)
		return brontide.Dial(idPriv, lnAddr)
	}
}
