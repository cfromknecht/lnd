package wtdb

import (
	"bytes"
	"io"

	"github.com/coreos/bbolt"
)

type ClientSession struct {
	Tower *Tower

	// TODO(conner): add SessionID derivation path
	Session *SessionInfo

	Updates []*SessionStateUpdate

	mu sync.Mutex
	db *ClientDB
}

func (db *ClientDB) CreateClientSession(tower *Tower,
	info *SessionInfo) (*ClientSessionInfo, error) {

	clientInfo := &ClientSessionInfo{
		Tower:   tower,
		Session: info,
		db:      db,
	}

	err := db.cfg.DB.Update(func(tx *bolt.Tx) error {
		return putClientSession(tx, clientInfo, true)
	})
	if err != nil {
		return nil, err
	}

	return clientInfo, nil
}

func (s *ClientSessionInfo) Accept(hintBlob *HintBlob) error {

}

func (s *ClientSession) AcceptStateUpdates(
	updates []*HintBlob) ([]*HintBlob, error) {

	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		currSession   *ClientSession
		failedUpdates []*HintBlob
	)

	err := s.db.Update(func(tx *bolt.Tx) error {
		var err error
		currSession, err = getClientSession(s.Session.ID[:])
		if err != nil {
			return err
		}

		for _, update := range update {
			err := currSession.Accept(update)
			switch err {
			case nil:
			case ErrNotWorthBackup, ErrSessionExhausted:
				failedUpdates = append(failedUpdates,
					update,
				)
			default:
				return err
			}

		}

		return putClientSession(tx, currSession, false)
	})
	if err != nil {
		return nil, err
	}

	s.Session = currSession.Session
	s.Updates = currSession.Updates

	return failedUpdates, nil
}

func putClientSession(tx *bolt.Tx, info *ClientSessionInfo, isInit bool) error {
	sessions := tx.Bucket(clientSessionBucket)
	if sessions == nil {
		return ErrCorruptClientDB
	}

	if isInit {
		infoBytes := sessions.Get(info.Session.ID[:])
		if infoBytes != nil {
			return ErrClientSessionAlreadyExists
		}
	}

	towerPubKey := info.Tower.IdentityKey.SerializeCompressed()
	if _, err := w.Write(towerPubKey); err != nil {
		return err
	}
	if err := info.Session.Encode(w); err != nil {
		return err
	}

	return sessions.Put(info.Session.ID[:], b.Bytes())
}

func getClientSession(tx *bolt.Tx,
	sessionID *SessionID) (*ClientSessionInfo, error) {

	sessions := tx.Bucket(clientSessionBucket)
	if sessions == nil {
		return nil, ErrCorruptClientDB
	}

	infoBytes := sessions.Get(sessionID[:])
	if infoBytes == nil {
		return nil, ErrClientSessionNotFound
	}

	info := &ClientSessionInfo{}

	infoReader := bytes.NewReader(infoBytes)

	var towerPubKeyBytes [33]byte
	if _, err := infoReader.Read(towerPubKeyBytes[:]); err != nil {
		return err
	}
	towerPubKey, err := btcec.ParsePubKey(towerPubKeyBytes[:], btcec.S256())
	if err != nil {
		return err
	}
	tower, err := fetchTower(tx, towerPubKey)
	if err != nil {
		return err
	}
	info.Tower = tower

	info.Session = &SessionInfo{}
	if err := info.Session.Decode(infoReader); err != nil {
		return err
	}

	return info, nil
}
