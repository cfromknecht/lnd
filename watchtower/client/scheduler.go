package client

type scheduler struct {
	sessions SessionManager
	channels ChannelManager

	newSessions       chan *sessionState
	exhaustedSessions chan *sessionState
	newUpdates        chan *wtdb.RevokedState
	readyTasks        chan *scheduleTask
	failedTasks       chan *scheduleTask
}

type scheduleTask struct {
	tower *wtdb.Tower
	msg   *lnwire.StateUpdate
}

func (t *scheduleTask) ID() wtdb.SessionID {
	return wtdb.NewSessionIDFromPubKey(t.tower.IdentityKey)
}

func (s *scheduler) schedule() {
	defer s.wg.Done()

	activeBatches := make(map[wtdb.SessionID]*sessionState)

	for {
		select {
		case session := <-s.newSessions:

		case session := <-s.exhaustedSessions:

		case update := <-s.newUpdates:
			// TODO(conner): chooses sessions
			// TODO(conner): spawn signing task
		case task := <-s.readyTasks:
			// TODO(conner): add to batch queue
			sessionID := task.ID()
			batch, ok := activeBatches[sessionID]
			if ok {
				batch.QueueState(task.msg)
				continue
			}

			batch = NewTowerQueue(
				task.Tower, defaultInterval, t.network,
			)
			activeBatches[sessionID] = batch
			batch.QueueState(task.msg)

		case task := <-s.failedTasks:
			sessionID := task.ID()

		case <-s.quit:
			return
		}
	}
}

func (s *scheduler) ScheduleStateUpdate(state *wtdb.RevokedState) error {
	select {
	case s.newUpdates <- state:
		return nil
	case <-s.quit:
		return ErrWtClientShuttingDown
	}
}
