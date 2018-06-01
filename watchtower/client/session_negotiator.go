package client

type SessionNegotiator interface {
	RequestSession()
	NewSessions() <-chan *ClientSessionInfo
}

type NegotiatorConfig struct {
	DB                *wtdb.ClientDB
	Canditates        TowerCandidateIterator
	Dial              func(*lnwire.NetAddress) (*brontide.Conn, error)
	Version           uint16
	UpdatesPerSession uint16
	NumTowers         uint16
	RewardRate        uint32
	SweepFeeRate      lnwallet.SatPerVByte
}

type sessionNegotiator struct {
	started uint32
	stopped uint32

	cfg *NegotiatorConfig

	mu            sync.Mutex
	isNegotiating bool

	dispatcher  chan struct{}
	newSessions chan *ClientSessionInfo

	wg   sync.WaitGroup
	quit chan struct{}
}

func NewSessionNegotiator(cfg *NegotiatorConfig) *sessionNegotiator {
	return &sessionNegotiator{
		cfg:         cfg,
		dispatcher:  make(chan struct{}, 1),
		newSessions: make(chan *ClientSessionInfo),
		make(chan struct{}),
	}
}

func (n *sessionNegotiator) NewSessions() <-chan *ClientSessionInfo {
	return n.newSessions
}

func (n *sessionNegotiator) RequestSession() {
	select {
	case n.dispatcher <- struct{}{}:
	default:
	}
}

func (n *sessionNegotiator) Start() error {
	if !atomic.CompareAndSwapUint32(n.started, 0, 1) {
		return nil
	}

	n.wg.Add(1)
	go n.negotiationDispatcher()

	return nil
}

func (n *sessionNegotiator) Stop() error {
	if !atomic.CompareAndSwapUint32(&n.stopped, 0, 1) {
		return nil
	}

	close(n.quit)
	n.wg.Wait()

	return nil
}

func (n *sessionNegotiator) negotiationDispatcher() {
	defer n.wg.Done()

	successfulNegotiations := make(chan *ClientSessionInfo)

	var isNegotiating bool
	for {
		select {
		case <-n.dispatcher:
			if isNegotiating {
				continue
			}
			isNegotiating = true

			// TODO(conner): consider reusing good towers

			c.wg.Add(1)
			go c.findTower(successfulNegotiations)

		case session := <-successfulNegotiations:
			select {
			case n.newSessions <- session:
			case <-n.quit:
				return ErrWtClientShuttingDown
			}

			isNegotiating = false

		case <-c.quit:
			return ErrWtClientShuttingDown
		}
	}
}

func (n *sessionNegotiator) findTower(
	successfulNegotiations chan *ClientSessionInfo) {

	defer n.wg.Done()

	for {
		addr, err := n.cfg.Candidates.Next()
		if err != nil {
			// TODO(conner): queue after timeout
			fmt.Printf("unable to get new watchtower addr: %v\n",
				err)
			return
		}

		done := n.initSession(addr, successfulNegotiations)
		if done {
			return
		}
	}
}

func (n *sessionNegotiator) initSession(addr *lnwire.NetAddress,
	successfulNegotiations chan *ClientSessionInfo) bool {

	conn, err := n.cfg.Dial(addr)
	if err != nil {
		fmt.Printf("unable to connect to watchtower=%v: %v\n",
			tower.addr, err)
		return false
	}

	tower, err := n.cfg.DB.CreateTower(addr)
	if err != nil {
		fmt.Printf("unable to create new watchtower: %v\n", err)
		return false
	}

	init := &wtwire.SessionInit{
		Version:      n.cfg.Version,
		MaxUpdates:   n.cfg.UpdatesPerSession,
		RewardRate:   n.cfg.RewardRate,
		SweepFeeRate: n.cfg.SweepFeeRate,
	}

	// TODO(conner): create random pubkey
	sessionID := wtdb.NewSessionIDFromPubKey(c.identityPriv.PubKey())

	// TODO(conner): set sweep address

	info := &wtdb.SessionInfo{
		ID:           sessionID,
		Version:      n.cfg.Version,
		MaxUpdates:   n.cfg.UpdatesPerSession,
		RewardRate:   n.cfg.RewardRate,
		SweepFeeRate: n.cfg.SweepFeeRate,
	}

	// Send SessionInit message.
	err = conn.SetWriteDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		fmt.Printf("unable to set write deadline: %v\n", err)
		return false
	}

	err = sendMessage(conn, init)
	if err != nil {
		fmt.Printf("unable to send init message to watchtower=%v: %v\n",
			tower.addr, err)
		return false
	}

	// Receive SessionAccept/SessionReject message.
	err = conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	if err != nil {
		fmt.Printf("unable to set read deadline: %v\n", err)
		return false
	}

	// Wait for response.
	rawMsg, err := conn.ReadNextMessage()
	if err != nil {
		fmt.Println("unable to read message from tower: %v\n", err)
		return false

	}

	msgReader := bytes.NewReader(rawMsg)
	msg, err := wtwire.ReadMessage(msgReader, 0)
	if err != nil {
		fmt.Println("unable to deserialize session-init response: %v\n",
			err)
		return false

	}

	switch resp := msg.(type) {
	case *wtwire.SessionAccept:
		info.RewardAddress = resp.RewardAddress

		// TODO(conner): write session

		session := &ClientSessionInfo{
			Tower:       tower,
			SessionInfo: info,
		}

		select {
		case successfulNegotiations <- session:
		case <-quit:
		}

		return true

	case *wtwire.SessionReject:
		return false
	default:
		fmt.Printf("received malformed response to session init")
		return false
	}
}
