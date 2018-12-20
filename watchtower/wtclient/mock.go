// +build dev

package wtclient

import (
	"net"
	"sync"
	"sync/atomic"

	"github.com/lightningnetwork/lnd/lnwire"
	"github.com/lightningnetwork/lnd/watchtower/wtdb"
	"github.com/lightningnetwork/lnd/watchtower/wtwire"
)

type towerPK [33]byte

type MockDB struct {
	nextTowerID uint64 // to be used atomically

	mu             sync.Mutex
	activeSessions map[wtdb.SessionID]*wtdb.ClientSessionInfo
	towerIndex     map[towerPK]uint64
	towers         map[uint64]*wtdb.Tower
}

func NewMockDB() *MockDB {
	return &MockDB{
		activeSessions: make(map[wtdb.SessionID]*wtdb.ClientSessionInfo),
		towerIndex:     make(map[towerPK]uint64),
		towers:         make(map[uint64]*wtdb.Tower),
	}
}

func (m *MockDB) CreateTower(lnAddr *lnwire.NetAddress) (*wtdb.Tower, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var tower *wtdb.Tower

	var towerPubKey towerPK
	copy(towerPubKey[:], lnAddr.IdentityKey.SerializeCompressed())

	towerID, ok := m.towerIndex[towerPubKey]
	if ok {
		tower = m.towers[towerID]
		tower.AddAddress(lnAddr.Address)
	} else {
		towerID = atomic.AddUint64(&m.nextTowerID, 1)
		tower = &wtdb.Tower{
			ID:          towerID,
			IdentityKey: lnAddr.IdentityKey,
			Addresses:   []net.Addr{lnAddr.Address},
		}
	}

	m.towerIndex[towerPubKey] = towerID
	m.towers[towerID] = tower

	return tower, nil
}

func (m *MockDB) GetChanBackupHeight(chanID lnwire.ChannelID) (uint64, error) {
	panic("not implemented")
}

func (m *MockDB) SetChanBackupHeight(chanID lnwire.ChannelID, commitHeight uint64, towerID uint32) error {
	panic("not implemented")
}

func (m *MockDB) MarkBackupIneligible(chanID lnwire.ChannelID, commitHeight uint64) error {
	return nil
}

func (m *MockDB) GetLastCommitHeight(lnwire.ChannelID) (uint64, error) {
	panic("not implemented")
}

func (m *MockDB) CommitBackup(chanID lnwire.ChannelID, commitHeight uint64,
	id *wtdb.SessionID, update *wtwire.StateUpdate) error {

	_ = &wtdb.SessionStateUpdate{
		ID:            *id,
		SeqNum:        update.SeqNum,
		LastApplied:   update.LastApplied,
		Hint:          update.Hint,
		EncryptedBlob: update.EncryptedBlob,
	}

	return nil
}

func (m *MockDB) ListActiveSessions() (map[wtdb.SessionID]*wtdb.ClientSessionInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sessions := make(map[wtdb.SessionID]*wtdb.ClientSessionInfo)
	for _, session := range m.activeSessions {
		sessions[session.ID] = session
	}

	return sessions, nil
}

func (m *MockDB) CreateClientSession(session *wtdb.ClientSessionInfo) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.activeSessions[session.ID] = session

	return nil
}
