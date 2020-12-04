package directory

import (
	"bytes"
	"errors"
	"fmt"
	"testing"

	"github.com/ORBAT/cloniks/crypto"
	"github.com/ORBAT/cloniks/crypto/sign"
	"github.com/ORBAT/cloniks/crypto/vrf"
	"github.com/ORBAT/cloniks/merkletree"
	"github.com/ORBAT/cloniks/protocol"
)

// A Tree is an authenticated key/value dictionary based on a prefix Merkle tree.
type Tree struct {
	pad    *merkletree.PAD
	tbs    map[string]*TemporaryBinding
	config *Config
}

// New constructs a new Tree given the key server's PAD
// config (i.e. epDeadline, vrfKey).
//
// signKey is the private key the key server uses to generate signed tree
// roots (STRs) and TBs.
// dirSize indicates the number of PAD snapshots the server keeps in memory.
func New(vrfKey vrf.PrivateKey, signKey sign.PrivateKey, dirSize uint64) (*Tree, error) {
	d := new(Tree)
	vrfPublicKey, ok := vrfKey.Public()
	if !ok {
		return nil, vrf.ErrGetPubKey
	}
	d.config = NewConfig(vrfPublicKey)
	pad, err := merkletree.NewPAD(d.config, signKey, vrfKey, dirSize)
	if err != nil {
		panic(err)
	}
	d.pad = pad
	d.tbs = make(map[string]*TemporaryBinding)
	return d, nil
}

// Update creates a new PAD snapshot updating this Tree. Deletes all issued TBs for the ending epoch
// as their corresponding mappings will have been inserted into the PAD.
func (d *Tree) Update() {
	d.pad.Update(d.config)
	// clear issued temporary bindings
	for key := range d.tbs {
		delete(d.tbs, key)
	}
}

// LatestSTR returns this Tree's latest STR.
func (d *Tree) LatestSTR() *SignedTreeRoot {
	return NewDirSTR(d.pad.LatestSTR())
}

// newTB creates a new temporary binding for the given name-to-value mapping.
// newTB() computes the private index for the name, and
// digitally signs the (index, value, latest STR signature) tuple.
func (d *Tree) newTB(name string, value []byte) *TemporaryBinding {
	index := d.pad.Index(name)
	return &TemporaryBinding{
		Index:     index,
		Value:     value,
		Signature: d.pad.Sign(d.LatestSTR().Signature, index, value),
	}
}

var ErrNoKeyOrValue = errors.New("no key or value provided")

type RegistrationResponse struct {
	AuthPath    *merkletree.AuthenticationPath
	TempBinding *TemporaryBinding
	Root        *SignedTreeRoot
}

// Register a new key/value mapping in this Tree. Inserts the new mapping into a pending version
// of the directory so it can be included in the snapshot taken at the end of the latest epoch, and
// returns a proof of absence for the value and a TemporaryBinding that can be used to prove that
// the Tree has promised to include the key in the next epoch.
//
// If the key already exists, returns an ErrKeyExists and proof (or if the key was in the current
// temporary bindings, a proof of current absence + non-nil TemporaryBinding).
func (d *Tree) Register(key string, value []byte) (resp RegistrationResponse, err error) {
	if len(key) == 0 || len(value) == 0 {
		return resp, ErrNoKeyOrValue
	}

	// check if key already exists
	resp.AuthPath, err = d.pad.Lookup(key)
	if err != nil {
		panic(fmt.Errorf("lookup in current epoch should never fail but got: %w", err))
	}

	if resp.AuthPath.ProofType() == merkletree.ProofOfInclusion {
		return resp, ErrKeyExists(key)
	}

	// check temporary bindings too in case the key was registered in this epoch
	if resp.TempBinding = d.tbs[key]; resp.TempBinding != nil {
		return resp, ErrKeyExists(key)
	}

	resp.TempBinding = d.newTB(key, value)
	if err := d.pad.Set(key, value); err != nil {
		resp.TempBinding = nil
		return resp, fmt.Errorf("setting value in PAD: %w", err)
	}

	d.tbs[key] = resp.TempBinding

	return
}

// KeyLookup gets the public key for the username indicated in the
// KeyLookupRequest req received from a CONIKS client from the latest
// snapshot of this Tree, and returns a protocol.Response.
// The response (which also includes the error code) is supposed to
// be sent back to the client.
//
// A request without a username is considered
// malformed, and causes KeyLookup() to return a
// message.NewErrorResponse(ErrMalformedMessage).
// If the username doesn't have an entry in the latest directory
// snapshot and also isn't pending registration (i.e. has a corresponding
// TB), KeyLookup() returns a message.NewKeyLookupProof(ap=proof of absence,
// str, nil, ReqNameNotFound).
// Otherwise, KeyLookup() returns a message.NewKeyLookupProof(ap=proof of
// absence, str, tb, ReqSuccess) if there is a corresponding TB for
// the username, but there isn't an entry in the directory yet, and a
// a message.NewKeyLookupProof(ap=proof of inclusion, str, nil, ReqSuccess)
// if there is.
// In any case, str is the signed tree root for the latest epoch.
// If KeyLookup() encounters an internal error at any point, it returns
// a message.NewErrorResponse(ErrDirectory).
func (d *Tree) KeyLookup(req *KeyLookupRequest) *Response {

	// make sure the request is well-formed
	if len(req.Username) <= 0 {
		return NewErrorResponse(protocol.ErrMalformedMessage)
	}

	ap, err := d.pad.Lookup(req.Username)
	if err != nil {
		return NewErrorResponse(protocol.ErrDirectory)
	}

	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		return NewKeyLookupProof(ap, d.LatestSTR(), nil, protocol.ReqSuccess)
	}
	// if not found in the tree, do lookup in tb array
	if tb := d.tbs[req.Username]; tb != nil {
		return NewKeyLookupProof(ap, d.LatestSTR(), tb, protocol.ReqSuccess)
	}
	return NewKeyLookupProof(ap, d.LatestSTR(), nil, protocol.ReqNameNotFound)
}

// KeyLookupInEpoch gets the public key for the username for a prior
// epoch in the directory history indicated in the
// KeyLookupInEpochRequest req received from a CONIKS client,
// and returns a protocol.Response.
// The response (which also includes the error code) is supposed to
// be sent back to the client.
//
// A request without a username or with an epoch greater than the latest
// epoch of this directory is considered malformed, and causes
// KeyLookupInEpoch() to return a
// message.NewErrorResponse(ErrMalformedMessage).
// If the username doesn't have an entry in the directory
// snapshot for the indicated epoch, KeyLookupInEpoch()
// returns a message.NewKeyLookupInEpochProof(ap=proof of absence, str,
// ReqNameNotFound).
// Otherwise, KeyLookupInEpoch() returns a
// message.NewKeyLookupInEpochProof(ap=proof of inclusion, str, ReqSuccess).
// In either case, str is a list of STRs for the epoch range [ep,
// d.LatestSTR().Epoch], where ep is the past epoch for which
// the client has requested the user's key.
// KeyLookupInEpoch() proofs do not include temporary bindings since
// the TB corresponding to a registered binding is discarded at the time
// the binding is included in a directory snapshot.
// If KeyLookupInEpoch() encounters an internal error at any point,
// it returns a message.NewErrorResponse(ErrDirectory).
func (d *Tree) KeyLookupInEpoch(req *KeyLookupInEpochRequest) *Response {

	// make sure the request is well-formed
	if len(req.Username) <= 0 ||
		req.Epoch > d.LatestSTR().Epoch {
		return NewErrorResponse(protocol.ErrMalformedMessage)
	}

	var strs []*SignedTreeRoot
	startEp := req.Epoch
	endEp := d.LatestSTR().Epoch

	ap, err := d.pad.LookupInEpoch(req.Username, startEp)
	if err != nil {
		return NewErrorResponse(protocol.ErrDirectory)
	}
	for ep := startEp; ep <= endEp; ep++ {
		str := NewDirSTR(d.pad.GetSTR(ep))
		strs = append(strs, str)
	}

	if bytes.Equal(ap.LookupIndex, ap.Leaf.Index) {
		return NewKeyLookupInEpochProof(ap, strs, protocol.ReqSuccess)
	}
	return NewKeyLookupInEpochProof(ap, strs, protocol.ReqNameNotFound)
}

// Monitor gets the directory proofs for the username for the range of
// epochs indicated in the MonitoringRequest req received from a
// CONIKS client, and returns a protocol.Response.
// The response (which also includes the error code) is supposed to
// be sent back to the client.
//
// A request without a username, with a start epoch greater than the
// latest epoch of this directory, or a start epoch greater than the
// end epoch is considered malformed, and causes Monitor() to return a
// message.NewErrorResponse(ErrMalformedMessage).
// Monitor() returns a message.NewMonitoringProof(ap, str).
// ap is a list of proofs of inclusion, and str is a list of STRs for
// the epoch range [startEpoch, endEpoch], where startEpoch
// and endEpoch are the epoch range endpoints indicated in the client's
// request. If req.endEpoch is greater than d.LatestSTR().Epoch,
// the end of the range will be set to d.LatestSTR().Epoch.
// If Monitor() encounters an internal error at any point,
// it returns a message.NewErrorResponse(ErrDirectory).
func (d *Tree) Monitor(req *MonitoringRequest) *Response {

	// make sure the request is well-formed
	if len(req.Username) <= 0 ||
		req.StartEpoch > d.LatestSTR().Epoch ||
		req.StartEpoch > req.EndEpoch {
		return NewErrorResponse(protocol.ErrMalformedMessage)
	}

	var strs []*SignedTreeRoot
	var aps []*merkletree.AuthenticationPath
	startEp := req.StartEpoch
	endEp := req.EndEpoch
	if endEp > d.LatestSTR().Epoch {
		endEp = d.LatestSTR().Epoch
	}
	for ep := startEp; ep <= endEp; ep++ {
		ap, err := d.pad.LookupInEpoch(req.Username, ep)
		if err != nil {
			return NewErrorResponse(protocol.ErrDirectory)
		}
		aps = append(aps, ap)
		str := NewDirSTR(d.pad.GetSTR(ep))
		strs = append(strs, str)
	}

	return NewMonitoringProof(aps, strs)
}

// GetSTRHistory gets the directory snapshots for the epoch range
// indicated in the STRHistoryRequest req received from a CONIKS auditor.
// The response (which also includes the error code) is supposed to
// be sent back to the auditor.
//
// A request with a start epoch greater than the
// latest epoch of this directory, or a start epoch greater than the
// end epoch is considered malformed, and causes
// GetSTRHistory() to return a
// message.NewErrorResponse(ErrMalformedMessage).
// GetSTRHistory() returns a message.NewSTRHistoryRange(strs).
// strs is a list of STRs for
// the epoch range [startEpoch, endEpoch], where startEpoch
// and endEpoch are the epoch range endpoints indicated in the client's
// request. If req.endEpoch is greater than d.LatestSTR().Epoch,
// the end of the range will be set to d.LatestSTR().Epoch.
func (d *Tree) GetSTRHistory(req *STRHistoryRequest) *Response {
	// make sure the request is well-formed
	if req.StartEpoch > d.LatestSTR().Epoch ||
		req.EndEpoch < req.StartEpoch {
		return NewErrorResponse(protocol.ErrMalformedMessage)
	}

	endEp := req.EndEpoch
	if req.EndEpoch > d.LatestSTR().Epoch {
		endEp = d.LatestSTR().Epoch
	}

	var strs []*SignedTreeRoot
	for ep := req.StartEpoch; ep <= endEp; ep++ {
		str := NewDirSTR(d.pad.GetSTR(ep))
		strs = append(strs, str)
	}

	return NewSTRHistoryRange(strs)
}

// NewTestTree creates a Tree used for testing server-side
// CONIKS operations.
func NewTestTree(t *testing.T) *Tree {
	vrfKey := crypto.NewStaticTestVRFKey()
	signKey := crypto.NewStaticTestSigningKey()
	d, err := New(vrfKey, signKey, 10)
	if err != nil {
		panic(err)
	}
	d.pad = merkletree.StaticPAD(t, d.config)
	return d
}

type ErrKeyExists string

func (e ErrKeyExists) Error() string {
	return "key already exists: " + string(e)
}

func (ErrKeyExists) Is(target error) bool {
	if target == nil {
		return false
	}
	_, ok := target.(interface{ IsKeyExistsError() })
	return ok
}

func (ErrKeyExists) IsKeyExistsError() {}

func IsKeyExistsError(e error) bool {
	if e == nil {
		return false
	}
	return errors.Is(e, ErrKeyExists(""))
}