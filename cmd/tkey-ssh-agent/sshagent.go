// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/gen2brain/beeep"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type SSHAgent struct {
	signer *Signer
	mutex  sync.Mutex
}

func NewSSHAgent(signer *Signer) *SSHAgent {
	return &SSHAgent{signer: signer}
}

func (s *SSHAgent) Serve(absSockPath string) error {
	listener, err := net.Listen("unix", absSockPath)
	if err != nil {
		return fmt.Errorf("Listen: %w", err)
	}
	le.Printf("Listening on %s\n", absSockPath)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return fmt.Errorf("Accept: %w", err)
		}
		le.Printf("Handling a client connection\n")
		go s.handleConn(conn)
	}
}

func (s *SSHAgent) handleConn(c net.Conn) {
	if err := agent.ServeAgent(s, c); !errors.Is(io.EOF, err) {
		le.Printf("Agent client connection ended with error: %s\n", err)
	}
}

// implementing agent.ExtendedAgent below

func (s *SSHAgent) List() ([]*agent.Key, error) {
	s.signer.Connect()
	if !s.signer.isConnected() {
		le.Printf("List: not connected, returning empty list\n")
		return []*agent.Key{}, nil
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	sshPub, err := s.signer.getSSHPub()
	if err != nil {
		return nil, err
	}
	return []*agent.Key{{
		Format:  sshPub.Type(),
		Blob:    sshPub.Marshal(),
		Comment: "TKey",
	}}, nil
}

var ErrNotImplemented = errors.New("not implemented")

func (s *SSHAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	s.signer.Connect()
	if !s.signer.isConnected() {
		return nil, ErrNoDevice
	}

	s.mutex.Lock()
	defer s.mutex.Unlock()
	sshPub, err := s.signer.getSSHPub()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(sshPub.Marshal(), key.Marshal()) {
		return nil, fmt.Errorf("pubkey mismatch")
	}
	sshSigner, err := ssh.NewSignerFromSigner(s.signer)
	if err != nil {
		return nil, fmt.Errorf("NewSignerFromSigner: %w", err)
	}

	timer := time.AfterFunc(4*time.Second, func() {
		err = beeep.Notify(progname, "Touch your Tillitis TKey to confirm SSH login.", "")
		if err != nil {
			le.Printf("Notify failed: %s\n", err)
		}
	})
	defer timer.Stop()

	le.Printf("Sign: user will have to touch the TKey\n")
	signature, err := sshSigner.Sign(rand.Reader, data)
	if err != nil {
		return nil, fmt.Errorf("Signer.Sign: %w", err)
	}
	return signature, nil
}

func (s *SSHAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	// we only do ed25519, so no need to care about flags
	return s.Sign(key, data)
}

func (s *SSHAgent) Extension(extensionType string, contents []byte) ([]byte, error) {
	// there is a new extensionType session-bind@openssh.com, but
	// implementation still seems optional
	// https://github.com/openssh/openssh-portable/blob/master/PROTOCOL.agent
	return nil, agent.ErrExtensionUnsupported
}

func (s *SSHAgent) Add(key agent.AddedKey) error {
	return ErrNotImplemented
}

func (s *SSHAgent) Remove(key ssh.PublicKey) error {
	return ErrNotImplemented
}

func (s *SSHAgent) RemoveAll() error {
	return ErrNotImplemented
}

func (s *SSHAgent) Lock(passphrase []byte) error {
	return ErrNotImplemented
}

func (s *SSHAgent) Unlock(passphrase []byte) error {
	return ErrNotImplemented
}

func (s *SSHAgent) Signers() ([]ssh.Signer, error) {
	return nil, ErrNotImplemented
}
