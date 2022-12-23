// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

package main

import (
	"crypto"
	"crypto/ed25519"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"

	"github.com/tillitis/tillitis-key1-apps/internal/util"
	"github.com/tillitis/tillitis-key1-apps/tk1"
	"github.com/tillitis/tillitis-key1-apps/tk1sign"
	"golang.org/x/crypto/ssh"
)

type constError string

func (err constError) Error() string {
	return string(err)
}

// nolint:typecheck // Avoid lint error when the embedding file is missing.
// Makefile copies the built app here ./app.bin
//
//go:embed app.bin
var appBinary []byte

const (
	// 4 chars each.
	wantAppName0 = "tk1 "
	wantAppName1 = "sign"
	// Custom errors
	ErrMaybeWrongDevice = constError("no TKey on the serial port, or it's not in firmware mode (and already running wrong app)")
	ErrNoDevice         = constError("no TKey connected")
)

type Signer struct {
	tk        *tk1.TillitisKey
	tkSigner  *tk1sign.Signer
	devPath   string
	speed     int
	enterUSS  bool
	fileUSS   string
	pinentry  string
	connected atomic.Bool
}

func NewSigner(devPathArg string, speedArg int, enterUSS bool, fileUSS string, pinentry string, exitFunc func(int)) *Signer {
	var signer Signer

	tk1.SilenceLogging()

	tk := tk1.New()

	tkSigner := tk1sign.New(tk)
	signer = Signer{
		tk:        tk,
		tkSigner:  &tkSigner,
		devPath:   devPathArg,
		speed:     speedArg,
		enterUSS:  enterUSS,
		fileUSS:   fileUSS,
		pinentry:  pinentry,
		connected: atomic.Bool{},
	}

	// Do nothing on HUP, in case old udev rule is still in effect
	handleSignals(func() {}, syscall.SIGHUP)

	// Start handling signals here to catch abort during USS entering
	handleSignals(func() {
		signer.disconnect()
		exitFunc(1)
	}, os.Interrupt, syscall.SIGTERM)

	return &signer
}

func (s *Signer) Connect() {
	le.Printf("Connecting!\n")

	s.disconnect()

	s.connect()
	if s.isConnected() {
		if err := s.maybeLoadApp(); err != nil {
			le.Printf("Failed to load app: %v\n", err)
			s.disconnect()
		}
	}
}

func (s *Signer) isConnected() bool {
	return s.connected.Load()
}

func (s *Signer) maybeLoadApp() error {
	if !s.isConnected() {
		return ErrNoDevice
	}

	if s.isWantedApp() {
		if s.enterUSS || s.fileUSS != "" {
			le.Printf("App already loaded, USS flags are ignored.\n")
		} else {
			le.Printf("App already loaded.\n")
		}
		s.printAuthorizedKey()
		return nil
	}

	if !s.isFirmwareMode() {
		// now we know that:
		// - loaded app does not have the wanted name
		// - device is not in firmware mode
		// anything else is possible
		return ErrMaybeWrongDevice
	}

	le.Printf("The TKey is in firmware mode.\n")
	var err error
	var secret []byte
	if s.enterUSS {
		var udi *tk1.UDI

		udi, err = s.tk.GetUDI()
		if err != nil {
			return fmt.Errorf("Failed to get UDI: %w", err)
		}

		secret, err = getSecret(udi.String(), s.pinentry)
		if err != nil {
			return fmt.Errorf("Failed to get USS: %w", err)
		}
	} else if s.fileUSS != "" {
		secret, err = util.ReadUSS(s.fileUSS)
		if err != nil {
			return fmt.Errorf("Failed to read uss-file %s: %w", s.fileUSS, err)
		}
	}

	le.Printf("Loading app...\n")
	if err = s.tk.LoadApp(appBinary, secret); err != nil {
		return fmt.Errorf("LoadApp: %w", err)
	}
	le.Printf("App loaded.\n")
	s.printAuthorizedKey()
	return nil
}

func (s *Signer) printAuthorizedKey() {
	if !s.isConnected() {
		return
	}

	sshPub, err := s.getSSHPub()
	if err != nil {
		le.Printf("Failed to getSSHPub: %s\n", err)
		return
	}

	le.Printf("Your SSH public key (on stdout):\n")
	fmt.Fprintf(os.Stdout, "%s", ssh.MarshalAuthorizedKey(sshPub))
}

func (s *Signer) getSSHPub() (ssh.PublicKey, error) {
	pub := s.Public()
	if pub == nil {
		return nil, fmt.Errorf("pubkey is nil")
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("NewPublicKey: %w", err)
	}
	return sshPub, nil
}

func (s *Signer) connect() {
	devPath := s.devPath
	if devPath == "" {
		var err error
		devPath, err = util.DetectSerialPort(false)
		if err != nil {
			le.Printf("Failed to detect ports: %v\n", err)
			s.connected.Store(false)
			return
		}
		le.Printf("Auto-detected serial port %s\n", devPath)
	}

	le.Printf("Connecting to TKey on serial port %s\n", devPath)
	if err := s.tk.Connect(devPath, tk1.WithSpeed(s.speed)); err != nil {
		le.Printf("Failed to connect: %v", err)
		s.connected.Store(false)
		return
	}

	s.connected.Store(true)
}

func (s *Signer) disconnect() {
	if s.tkSigner == nil {
		return
	}

	if !s.isConnected() {
		le.Printf("Disconnect: not connected\n")
		return
	}

	if err := s.tkSigner.Close(); err != nil {
		le.Printf("Disconnect: Close failed: %s\n", err)
	}

	s.connected.Store(false)
}

func (s *Signer) isWantedApp() bool {
	if !s.isConnected() {
		return false
	}

	nameVer, err := s.tkSigner.GetAppNameVersion()
	if err != nil {
		if !errors.Is(err, io.EOF) {
			le.Printf("GetAppNameVersion: %s\n", err)
		}
		return false
	}
	// not caring about nameVer.Version
	if wantAppName0 != nameVer.Name0 || wantAppName1 != nameVer.Name1 {
		return false
	}
	return true
}

func (s *Signer) isFirmwareMode() bool {
	if !s.isConnected() {
		return false
	}

	_, err := s.tk.GetNameVersion()
	return err == nil
}

// implementing crypto.Signer below

func (s *Signer) Public() crypto.PublicKey {
	if !s.isConnected() {
		return nil
	}

	pub, err := s.tkSigner.GetPubkey()
	if err != nil {
		le.Printf("GetPubKey failed: %s\n", err)
		return nil
	}
	return ed25519.PublicKey(pub)
}

func (s *Signer) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) ([]byte, error) {
	if !s.isConnected() {
		return nil, ErrNoDevice
	}

	// The Ed25519 signature must be made over unhashed message. See:
	// https://cs.opensource.google/go/go/+/refs/tags/go1.18.4:src/crypto/ed25519/ed25519.go;l=80
	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("message must not be hashed")
	}

	signature, err := s.tkSigner.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("Sign: %w", err)
	}
	return signature, nil
}

func handleSignals(action func(), sig ...os.Signal) {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, sig...)
	go func() {
		for {
			<-ch
			action()
		}
	}()
}
