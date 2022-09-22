// Copyright (C) 2022 - Tillitis AB
// SPDX-License-Identifier: GPL-2.0-only

// Package mkdf provides a connection to a Tillitis Key 1 security stick.
// To create a new connection:
//
//	tk, err := mkdf.New(*port, *speed)
//
// Then you can start using it by asking it to identify itself:
//
//	nameVer, err := tk.GetNameVersion()
//
// Or uploading and starting an app on the stick:
//
//	err = tk.LoadAppFromFile(*fileName)
//
// After this, you will have to switch to a new protocol specific to
// the app, see for instance the package
// github.com/tillitis/tillitis-key1-apps/mkdfsign for one such app
// specific protocol.
//
// When writing your app specific protocol you might still want to use
// the framing protocol provided here. See GenFrameBuf() and
// ReadFrame().
package mkdf

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	"go.bug.st/serial"
	"golang.org/x/crypto/blake2s"
)

var le = log.New(os.Stderr, "", 0)

func SilenceLogging() {
	le.SetOutput(io.Discard)
}

const (
	StatusOK  = 0x00
	StatusBad = 0x01
)

// TillitisKey is a serial connection to a Tillitis Key 1 and the
// commands that the firmware supports.
type TillitisKey struct {
	conn serial.Port
}

// New() opens a connection to the Tillitis Key 1 at the serial device
// port at indicated speed.
func New(port string, speed int) (TillitisKey, error) {
	var tk TillitisKey
	var err error

	tk.conn, err = serial.Open(port, &serial.Mode{BaudRate: speed})
	if err != nil {
		return tk, fmt.Errorf("serial.Open %s: %w", port, err)
	}

	return tk, nil
}

// Close the connection to the TK1
func (tk TillitisKey) Close() error {
	if err := tk.conn.Close(); err != nil {
		return fmt.Errorf("conn.Close: %w", err)
	}
	return nil
}

// SetReadTimeout sets the timeout of the underlying serial connection to the
// TK1. Pass 0 seconds to not have any timeout. Note that the timeout
// implemented in the serial lib only works for simple Read(). E.g.
// io.ReadFull() will Read() until the buffer is full.
func (tk TillitisKey) SetReadTimeout(seconds int) error {
	var t time.Duration = -1
	if seconds > 0 {
		t = time.Duration(seconds) * time.Second
	}
	if err := tk.conn.SetReadTimeout(t); err != nil {
		return fmt.Errorf("SetReadTimeout: %w", err)
	}
	return nil
}

type NameVersion struct {
	Name0   string
	Name1   string
	Version uint32
}

func (n *NameVersion) Unpack(raw []byte) {
	n.Name0 = fmt.Sprintf("%c%c%c%c", raw[3], raw[2], raw[1], raw[0])
	n.Name1 = fmt.Sprintf("%c%c%c%c", raw[7], raw[6], raw[5], raw[4])
	n.Version = binary.LittleEndian.Uint32(raw[8:12])
}

// GenFrameBuf could take CmdCode as param, and set it in TX. It would
// then not need to take CmdLen as param, but instead know every the
// CmdLen for every CmdCode.

// ReadFrame could take the expected ResponseCode as param. It could
// then do the check, since this is always done by the caller. It
// would then not need to take expected CmdLen of the response, but
// could know about them all (as above).

// I think these changes would work in all current cases, but could it
// limit the use of GenFrameBuf/ReadFrame in some way?

// GetNameVersion() gets the name and version from the TK1 firmware
func (tk TillitisKey) GetNameVersion() (*NameVersion, error) {
	tx, err := GenFrameBuf(2, DestFW, CmdLen1)
	if err != nil {
		return nil, err
	}

	if err = tk.SetReadTimeout(2); err != nil {
		return nil, err
	}

	// Set command code
	tx[1] = byte(cmdGetNameVersion)

	Dump("GetNameVersion tx", tx)
	if err = tk.Write(tx); err != nil {
		return nil, err
	}

	_, rx, err := tk.ReadFrame(CmdLen32, DestFW)
	if err != nil {
		return nil, fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[0] != byte(rspGetNameVersion) {
		return nil, fmt.Errorf("Expected rspGetNameVersion, got 0x%x", rx[0])
	}

	if err = tk.SetReadTimeout(0); err != nil {
		return nil, fmt.Errorf("SetReadTimeout: %w", err)
	}

	nameVer := &NameVersion{}
	nameVer.Unpack(rx[1:])

	return nameVer, nil
}

// LoadAppFromFile() loads and runs a raw binary file from fileName into the TK1
func (tk TillitisKey) LoadAppFromFile(fileName string) error {
	content, err := os.ReadFile(fileName)
	if err != nil {
		return fmt.Errorf("ReadFile: %w", err)
	}

	return tk.LoadApp(content)
}

// LoadApp loads the contents of bin into the TK1 and runs it after
// verifying that the digest is the same
func (tk TillitisKey) LoadApp(bin []byte) error {
	binLen := len(bin)
	if binLen > 65536 {
		return fmt.Errorf("File to big")
	}

	le.Printf("app size: %v, 0x%x, 0b%b\n", binLen, binLen, binLen)

	err := tk.setAppSize(binLen)
	if err != nil {
		return err
	}

	// Load the file
	var offset int
	for nsent := 0; offset < binLen; offset += nsent {
		nsent, err = tk.loadAppData(bin[offset:])
		if err != nil {
			return fmt.Errorf("loadAppData: %w", err)
		}
	}
	if offset > binLen {
		return fmt.Errorf("transmitted more than expected")
	}

	le.Printf("Going to getappdigest\n")
	appDigest, err := tk.getAppDigest()
	if err != nil {
		return err
	}

	digest := blake2s.Sum256(bin)

	le.Printf("Digest from host:\n")
	printDigest(digest)
	le.Printf("Digest from device:\n")
	printDigest(appDigest)

	if appDigest != digest {
		return fmt.Errorf("Different digests")
	}
	le.Printf("Same digests!\n")

	// Run the app
	le.Printf("Running the app\n")
	return tk.runApp()
}

// setAppSize() sets the size of the app to be loaded into the TK1.
func (tk TillitisKey) setAppSize(size int) error {
	tx, err := GenFrameBuf(2, DestFW, CmdLen32)
	if err != nil {
		return err
	}

	// Set command code
	tx[1] = byte(cmdLoadAppSize)

	// Set size
	tx[2] = byte(size)
	tx[3] = byte(size >> 8)
	tx[4] = byte(size >> 16)
	tx[5] = byte(size >> 24)

	Dump("SetAppSize tx", tx)
	if err = tk.Write(tx); err != nil {
		return err
	}

	_, rx, err := tk.ReadFrame(CmdLen4, DestFW)
	if err != nil {
		return fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[0] != byte(rspLoadAppSize) {
		return fmt.Errorf("Expected rspLoadAppSize, got 0x%x", rx[0])
	}
	if rx[1] != StatusOK {
		return fmt.Errorf("SetAppSize NOK")
	}

	return nil
}

// loadAppData() loads a chunk of the raw app binary into the TK1 and
// waits for a reply.
func (tk TillitisKey) loadAppData(content []byte) (int, error) {
	tx, err := GenFrameBuf(2, DestFW, CmdLen128)
	if err != nil {
		return 0, err
	}

	tx[1] = byte(cmdLoadAppData)

	payload := make([]byte, CmdLen128.Bytelen()-1)
	copied := copy(payload, content)

	// Add padding if not filling the payload buffer.
	if copied < len(payload) {
		padding := make([]byte, len(payload)-copied)
		copy(payload[copied:], padding)
	}

	copy(tx[2:], payload)

	Dump("LoadAppData tx", tx)

	if err = tk.Write(tx); err != nil {
		return 0, err
	}

	// Wait for reply
	_, rx, err := tk.ReadFrame(CmdLen4, DestFW)
	if err != nil {
		return 0, fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[0] != byte(rspLoadAppData) {
		return 0, fmt.Errorf("Expected rspLoadAppData, got %v", rx[0])
	}

	if rx[1] != StatusOK {
		return 0, fmt.Errorf("LoadAppData NOK")
	}

	return copied, nil
}

// getAppDigest() asks for an app digest from the TK1.
func (tk TillitisKey) getAppDigest() ([32]byte, error) {
	var md [32]byte

	tx, err := GenFrameBuf(2, DestFW, CmdLen1)
	if err != nil {
		return md, err
	}

	tx[1] = byte(cmdGetAppDigest)
	Dump("GetDigest tx", tx)

	if err = tk.Write(tx); err != nil {
		return md, err
	}

	// Wait for reply
	_, rx, err := tk.ReadFrame(CmdLen128, DestFW)
	if err != nil {
		return md, fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[0] != byte(rspGetAppDigest) {
		return md, fmt.Errorf("Expected rspGetAppDigest, got %v", rx[0])
	}

	copy(md[:], rx[1:])

	return md, nil
}

// runApp() runs the loaded app, if any, in the TK1.
func (tk TillitisKey) runApp() error {
	tx, err := GenFrameBuf(2, DestFW, CmdLen1)
	if err != nil {
		return err
	}

	tx[1] = byte(cmdRunApp)

	if err = tk.Write(tx); err != nil {
		return err
	}

	// Wait for reply
	_, rx, err := tk.ReadFrame(CmdLen4, DestFW)
	if err != nil {
		return fmt.Errorf("ReadFrame: %w", err)
	}

	if rx[0] != byte(rspRunApp) {
		return fmt.Errorf("Expected rspRunApp, got %v", rx[0])
	}

	if rx[1] != StatusOK {
		return fmt.Errorf("RunApp NOK")
	}

	return nil
}

func printDigest(md [32]byte) {
	digest := ""
	for j := 0; j < 4; j++ {
		for i := 0; i < 8; i++ {
			digest += fmt.Sprintf("%02x", md[i+8*j])
		}
		digest += " "
	}
	le.Printf(digest + "\n")
}
