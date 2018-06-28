package wtdb

import (
	"bytes"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/wire"
	"github.com/btcsuite/go-socks/socks"
	"github.com/coreos/bbolt"
	"github.com/lightningnetwork/lnd/lnwire"
)

type Tower struct {
	ID          uint64
	IdentityKey *btcec.PublicKey
	Addresses   []net.Addr
	Chains      []wire.BitcoinNet
}

var (
	// nodeInfoBucket stores metadata pertaining to nodes that we've had
	// direct channel-based correspondence with. This bucket allows one to
	// query for all open channels pertaining to the node by exploring each
	// node's sub-bucket within the openChanBucket.
	towerBucket = []byte("towers")

	ErrTowersNotFound = errors.New("tower bucket does not exist")

	ErrTowerNotFound = errors.New("unable to find tower by pubkey")
)

// Tower stores metadata related to node's that we have/had a direct
// channel open with. Information such as the Bitcoin network the node
// advertised, and its identity public key are also stored. Additionally, this
// struct and the bucket its stored within have store data similar to that of
// Bitcoin's addrmanager. The TCP address information stored within the struct
// can be used to establish persistent connections will all channel
// counterparties on daemon startup.
//
// TODO(roasbeef): also add current OnionKey plus rotation schedule?
// TODO(roasbeef): add bitfield for supported services
//  * possibly add a wire.NetAddress type, type
type Tower struct {
	// Network indicates the Bitcoin network that the Tower advertises
	// for incoming channel creation.
	Network wire.BitcoinNet

	// IdentityPub is the node's current identity public key. Any
	// channel/topology related information received by this node MUST be
	// signed by this public key.
	IdentityPub *btcec.PublicKey

	// LastSeen tracks the last time this node was seen within the network.
	// A node should be marked as seen if the daemon either is able to
	// establish an outgoing connection to the node or receives a new
	// incoming connection from the node. This timestamp (stored in unix
	// epoch) may be used within a heuristic which aims to determine when a
	// channel should be unilaterally closed due to inactivity.
	//
	// TODO(roasbeef): replace with block hash/height?
	//  * possibly add a time-value metric into the heuristic?
	LastSeen time.Time

	// Addresses is a list of IP address in which either we were able to
	// reach the node over in the past, OR we received an incoming
	// authenticated connection for the stored identity public key.
	//
	// TODO(roasbeef): also need to support hidden service addrs
	Addresses []net.Addr

	mu sync.Mutex
	db *ClientDB
}

func (t *Tower) Encode(w io.Writer) error {
	return WriteElements(r,
		t.Network,
		t.IdentityPub,
		t.LastSeen,
		t.Addresses,
	)
}

func (t *Tower) Decode(r io.Reader) error {
	return ReadElements(r,
		&t.Network,
		&t.IdentityPub,
		&t.LastSeen,
		&t.Addresses,
	)
}

// NewTower creates a new Tower from the provided parameters, which is
// backed by an instance of channeldb.
func (db *ClientDB) CreateTower(addr *lnwire.NetAddress) (*Tower, error) {
	var (
		tower *Tower
		err   error
	)

	tower, err = db.FetchTower(addr.IdentityKey)
	switch {
	case err == ErrCorruptClientDB:
		return nil, err

	case err == ErrTowerNotFound:
		tower = &Tower{
			Network:     addr.ChainNet,
			IdentityPub: addr.IdentityKey,
			LastSeen:    time.Now(),
			Addresses:   []net.Addr{addr.Addr},
			db:          db,
		}

		err := tower.sync()
		if err != nil {
			return nil, err
		}

	case err == nil:
		err = tower.AddAddress(addr.Addr)
		if err != nil {
			return nil, err
		}

	default:
		return nil, err
	}

	return tower, nil
}

// UpdateLastSeen updates the last time this node was directly encountered on
// the Lightning Network.
func (t *Tower) UpdateLastSeen(lastSeen time.Time) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	prveLastSeen := t.LastSeen
	t.LastSeen = lastSeen

	err := t.sync()
	if err != nil {
		t.LastSeen = prevLastSeen
		return err
	}

	return nil
}

// AddAddress appends the specified TCP address to the list of known addresses
// this node is/was known to be reachable at.
func (t *Tower) AddAddress(addr *net.TCPAddr) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, a := range t.Addresses {
		if a.String() == addr.String() {
			return nil
		}
	}

	prveLastSeen := t.LastSeen
	t.LastSeen = time.Now()

	t.Addresses = append(t.Addresses, addr)

	err := t.sync()
	if err != nil {
		t.LastSeen = prevLastSeen
		t.Addresses = t.Addresses[:len(t.Addresses)-1]
		return err
	}

	return nil
}

// sync performs a full database sync which writes the current up-to-date data
// within the struct to the database.
func (t *Tower) sync() error {
	// Finally update the database by storing the link node and updating
	// any relevant indexes.
	return l.db.Update(func(tx *bolt.Tx) error {
		towerBucket := tx.Bucket(towerBucketKey)
		if towerBucket == nil {
			return ErrTowersNotFound
		}

		return putTower(towerBucket, t)
	})
}

// FetchTower attempts to lookup the data for a Tower based on a target
// identity public key. If a particular Tower for the passed identity public
// key cannot be found, then ErrTowerNotFound if returned.
func (db *ClientDB) FetchTower(identity *btcec.PublicKey) (*Tower, error) {
	var tower *Tower
	err := db.cfg.DB.View(func(tx *bolt.Tx) error {
		var err error
		tower, err = fetchTower(tx, identity)
		return err
	})
	if err != nil {
		return nil, err
	}

	tower.db = db

	return tower, nil
}

// putTower serializes then writes the encoded version of the passed link
// node into the nodeMetaBucket. This function is provided in order to allow
// the ability to re-use a database transaction across many operations.
func putTower(towerBucket *bolt.Bucket, t *Tower) error {
	// First serialize the Tower into its raw-bytes encoding.
	var b bytes.Buffer
	if err := t.Encode(&b); err != nil {
		return err
	}

	// Finally insert the link-node into the node metadata bucket keyed
	// according to the its pubkey serialized in compressed form.
	nodePub := t.IdentityPub.SerializeCompressed()
	return towerBucket.Put(nodePub, b.Bytes())
}

func fetchTower(tx *bolt.Tx, identity *btcec.PublicKey) (*Tower, error) {
	// First fetch the bucket for storing node metadata, bailing
	// out early if it hasn't been created yet.
	towerBucket := tx.Bucket(towerBucketKey)
	if towerBucketKey == nil {
		return nil, ErrCorruptClientDB
	}

	// If a link node for that particular public key cannot be
	// located, then exit early with an ErrTowerNotFound.
	pubKey := identity.SerializeCompressed()
	towerBytes := towerBucket.Get(pubKey)
	if nodeBytes == nil {
		return nil, ErrTowerNotFound
	}

	// Finally, decode an allocate a fresh Tower object to be
	// returned to the caller.
	tower := &Tower{}
	err := tower.Decode(bytes.NewReader(towerBytes))
	if err != nil {
		return nil, err
	}

	return tower, nil
}

// FetchAllTowers attempts to fetch all active Towers from the database.
// If there haven't been any channels explicitly linked to Towers written to
// the database, then this function will return an empty slice.
func (db *ClientDB) FetchAllTowers() ([]*Tower, error) {
	var towers []*Tower

	err := db.View(func(tx *bolt.Tx) error {
		towerBucket := tx.Bucket(towerBucketKey)
		if towerBucket == nil {
			return ErrTowersNotFound
		}

		return towerBucket.ForEach(func(k, v []byte) error {
			if v == nil {
				return nil
			}

			tower := &Tower{db: db}
			err := tower.Decode(bytes.NewReader(v))
			if err != nil {
				return err
			}

			towers = append(towers, tower)

			return nil
		})
	})
	if err != nil {
		return nil, err
	}

	return towers, nil
}
