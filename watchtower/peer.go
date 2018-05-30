package watchtower

import (
	"bytes"
	"time"

	"github.com/lightningnetwork/lnd/brontide"
	"github.com/lightningnetwork/watchtower/wtwire"
)

var (
	ErrPeerShuttingDown = erros.New("peer shutting down")
)

type Peer interface {
	SendMessage(msg *wtwire.Message, sync bool) error
}

type peer struct {
	conn *brontide.Conn

	buffer bytes.Buffer

	readTimeout  time.Duration
	writeTimeout time.Duration
}

func (p *peer) SendMessage(msg *wtwire.Message, sync bool) error {
	if !sync {
		p.queueMsg(msg, nil)
		return nil
	}

	errChan := make(chan error, 1)
	p.queueMsg(msg, errChan)

	select {
	case err := <-errChan:
		return err
	case <-p.quit:
		return ErrPeerShuttingDown
	}

}

func (p *peer) writeHandler() {
	defer p.wg.Done()
	defer p.Disconnect()

	var exitErr error

out:
	for {
		select {
		case outMsg := <-p.outgoingQueue:
			p.buffer.Reset()
			err := wtwire.WriteMessage(&p.buffer, outMsg.msg, 0)
			if err != nil {

			}
			err = p.conn.SetWriteDeadline(p.writeTimeout)
			if err != nil {
				return err
			}

			_, err = p.conn.WriteMessage(b.Bytes())
			if outMsg.errChan != nil {
				outMsg.errChan <- err
			}

			if err != nil {
				exitErr = fmt.Errorf("uanble to write "+
					"message: %v", err)
				break out
			}

		case <-p.quit:
			exitErr = ErrPeerShuttingDown
			break out
		}
	}

	fmt.Printf("writeHandler for peer %v exiting: %v", p.conn, exitErr)
}

type outgoingMsg struct {
	msg     *wtire.Message
	errChan chan error
}

func (p *peer) queueMsg(msg *wtwire.Message, errChan chan error) {
	select {
	case p.outgoingQueue <- outgoingMsg{msg, errChan}:
	case <-p.quit:
		// TODO(conner): log unable to queue msg
		if errChan != nil {
			errChan <- ErrPeerShuttingDown
		}
	}
}
