package wtdb

import (
	"encoding/binary"
	"io"

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

// NewTower creates a new Tower from the provided parameters, which is
// backed by an instance of channeldb.
func (db *ClientDB) NewTower(bitNet wire.BitcoinNet, pub *btcec.PublicKey,
	addr net.Addr) (*Tower, error) {

	t := &Tower{
		Network:     bitNet,
		IdentityPub: pub,
		LastSeen:    time.Now(),
		Addresses:   []net.Addr{addr},
		db:          db,
	}

	err := t.sync()
	if err != nil {
		return nil, err
	}

	return t, nil
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
func (l *Tower) AddAddress(addr *net.TCPAddr) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	for _, a := range t.Addresses {
		if a.String() == addr.String() {
			return nil
		}
	}

	t.Addresses = append(t.Addresses, addr)

	err := t.sync()
	if err != nil {
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

// putTower serializes then writes the encoded version of the passed link
// node into the nodeMetaBucket. This function is provided in order to allow
// the ability to re-use a database transaction across many operations.
func putTower(towerBucket *bolt.Bucket, t *Tower) error {
	// First serialize the Tower into its raw-bytes encoding.
	var b bytes.Buffer
	if err := serializeTower(&b, t); err != nil {
		return err
	}

	// Finally insert the link-node into the node metadata bucket keyed
	// according to the its pubkey serialized in compressed form.
	nodePub := t.IdentityPub.SerializeCompressed()
	return towerBucket.Put(nodePub, b.Bytes())
}

// FetchTower attempts to lookup the data for a Tower based on a target
// identity public key. If a particular Tower for the passed identity public
// key cannot be found, then ErrNodeNotFound if returned.
func (db *ClientDB) FetchTower(identity *btcec.PublicKey) (*Tower, error) {
	var (
		tower *Tower
		err   error
	)

	err = db.View(func(tx *bolt.Tx) error {
		// First fetch the bucket for storing node metadata, bailing
		// out early if it hasn't been created yet.
		towerBucket := tx.Bucket(towerBucketKey)
		if towerBucketKey == nil {
			return ErrTowersNotFound
		}

		// If a link node for that particular public key cannot be
		// located, then exit early with an ErrNodeNotFound.
		pubKey := identity.SerializeCompressed()
		towerBytes := towerBucket.Get(pubKey)
		if nodeBytes == nil {
			return ErrNodeNotFound
		}

		// Finally, decode an allocate a fresh Tower object to be
		// returned to the caller.
		towerReader := bytes.NewReader(towerBytes)
		tower, err = deserializeTower(towerReader)
		return err
	})
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

			towerReader := bytes.NewReader(v)
			tower, err := deserializeTower(towerReader)
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

func serializeTower(w io.Writer, t *Tower) error {
	var buf [8]byte

	byteOrder.PutUint32(buf[:4], uint32(t.Network))
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	serializedID := t.IdentityPub.SerializeCompressed()
	if _, err := w.Write(serializedID); err != nil {
		return err
	}

	seenUnix := uint64(t.LastSeen.Unix())
	byteOrder.PutUint64(buf[:], seenUnix)
	if _, err := w.Write(buf[:]); err != nil {
		return err
	}

	numAddrs := uint32(len(t.Addresses))
	byteOrder.PutUint32(buf[:4], numAddrs)
	if _, err := w.Write(buf[:4]); err != nil {
		return err
	}

	for _, addr := range t.Addresses {
		if err := serializeAddr(w, addr); err != nil {
			return err
		}
	}

	return nil
}

func deserializeTower(r io.Reader) (*Tower, error) {
	var (
		err error
		buf [8]byte
	)

	node := &Tower{}

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return nil, err
	}
	node.Network = wire.BitcoinNet(byteOrder.Uint32(buf[:4]))

	var pub [33]byte
	if _, err := io.ReadFull(r, pub[:]); err != nil {
		return nil, err
	}
	node.IdentityPub, err = btcec.ParsePubKey(pub[:], btcec.S256())
	if err != nil {
		return nil, err
	}

	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return nil, err
	}
	node.LastSeen = time.Unix(int64(byteOrder.Uint64(buf[:])), 0)

	if _, err := io.ReadFull(r, buf[:4]); err != nil {
		return nil, err
	}
	numAddrs := byteOrder.Uint32(buf[:4])

	node.Addresses = make([]net.Addr, numAddrs)
	for i := uint32(0); i < numAddrs; i++ {
		addr, err := deserializeAddr(r)
		if err != nil {
			return nil, err
		}
		node.Addresses[i] = addr
	}

	return node, nil
}

// deserializeAddr reads the serialized raw representation of an address and
// deserializes it into the actual address, to avoid performing address
// resolution in the database module
func deserializeAddr(r io.Reader) (net.Addr, error) {
	var scratch [8]byte
	var address net.Addr

	if _, err := r.Read(scratch[:1]); err != nil {
		return nil, err
	}

	// TODO(roasbeef): also add onion addrs
	switch addressType(scratch[0]) {
	case tcp4Addr:
		addr := &net.TCPAddr{}
		var ip [4]byte
		if _, err := r.Read(ip[:]); err != nil {
			return nil, err
		}
		addr.IP = (net.IP)(ip[:])
		if _, err := r.Read(scratch[:2]); err != nil {
			return nil, err
		}
		addr.Port = int(byteOrder.Uint16(scratch[:2]))
		address = addr
	case tcp6Addr:
		addr := &net.TCPAddr{}
		var ip [16]byte
		if _, err := r.Read(ip[:]); err != nil {
			return nil, err
		}
		addr.IP = (net.IP)(ip[:])
		if _, err := r.Read(scratch[:2]); err != nil {
			return nil, err
		}
		addr.Port = int(byteOrder.Uint16(scratch[:2]))
		address = addr
	default:
		return nil, ErrUnknownAddressType
	}

	return address, nil
}

// serializeAddr serializes an address into a raw byte representation so it
// can be deserialized without requiring address resolution
func serializeAddr(w io.Writer, address net.Addr) error {

	switch addr := address.(type) {
	case *net.TCPAddr:
		return encodeTCPAddr(w, addr)

	// If this is a proxied address (due to the connection being
	// established over a SOCKs proxy, then we'll convert it into its
	// corresponding TCP address.
	case *socks.ProxiedAddr:
		// If we can't parse the host as an IP (though we should be
		// able to at this point), then we'll skip this address all
		// together.
		//
		// TODO(roasbeef): would be nice to be able to store hosts
		// though...
		ip := net.ParseIP(addr.Host)
		if ip == nil {
			return nil
		}

		tcpAddr := &net.TCPAddr{
			IP:   ip,
			Port: addr.Port,
		}
		return encodeTCPAddr(w, tcpAddr)
	}

	return nil
}
