package wtclient

import "errors"

var (
	ErrClientExiting = errors.New("watchtower client shutting down")

	ErrNoNetwork = errors.New("no network set, must be tor or clear net")

	ErrTowerCandidatesExhausted = errors.New("unable to find watchtower " +
		"candidate")
)
