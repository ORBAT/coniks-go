package directory

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ORBAT/cloniks/crypto"
	"github.com/ORBAT/cloniks/merkletree"
	"github.com/ORBAT/cloniks/protocol"
)

func TestDirectoryKeyLookupInEpochBadEpoch(t *testing.T) {
	d := NewTestTree(t)
	for _, tc := range []struct {
		name     string
		userName string
		ep       uint64
		want     error
	}{
		{"invalid username", "", 0, protocol.ErrMalformedMessage},
		{"bad end epoch", "Alice", 2, protocol.ErrMalformedMessage},
	} {
		res := d.KeyLookupInEpoch(&KeyLookupInEpochRequest{
			Username: tc.userName,
			Epoch:    tc.ep,
		})
		if res.Error != tc.want {
			t.Errorf("Expect ErrMalformedMessage for %s", tc.name)
		}
	}
}

func TestBadRequestMonitoring(t *testing.T) {
	d := NewTestTree(t)

	for _, tc := range []struct {
		name     string
		userName string
		startEp  uint64
		endEp    uint64
		want     error
	}{
		{"invalid username", "", 0, 0, protocol.ErrMalformedMessage},
		{"bad end epoch", "Alice", 4, 2, protocol.ErrMalformedMessage},
		{"out-of-bounds", "Alice", 2, d.LatestSTR().Epoch, protocol.ErrMalformedMessage},
	} {
		res := d.Monitor(&MonitoringRequest{
			Username:   tc.userName,
			StartEpoch: tc.startEp,
			EndEpoch:   tc.endEp,
		})
		if res.Error != tc.want {
			t.Errorf("Expect ErrMalformedMessage for %s", tc.name)
		}
	}
}

func TestBadRequestGetSTRHistory(t *testing.T) {
	d := NewTestTree(t)
	d.Update()

	for _, tc := range []struct {
		name    string
		startEp uint64
		endEp   uint64
		want    error
	}{
		{"bad end epoch", 4, 2, protocol.ErrMalformedMessage},
		{"out-of-bounds", 6, d.LatestSTR().Epoch, protocol.ErrMalformedMessage},
	} {
		res := d.GetSTRHistory(&STRHistoryRequest{
			StartEpoch: tc.startEp,
			EndEpoch:   tc.endEp,
		})
		if res.Error != tc.want {
			t.Errorf("Expect ErrMalformedMessage for %s", tc.name)
		}
	}
}


var signKey = crypto.NewStaticTestSigningKey()
var vrfKey = crypto.NewStaticTestVRFKey()
func newEmptyTree(t *testing.T) *Tree {
	tree, err := New(vrfKey, signKey, 10)
	require.NoError(t, err, "create test tree")
	return tree
}

func newTreeWithKeys(keys ...string) func(t *testing.T) *Tree {
	return func(t *testing.T) *Tree {
		tree := newEmptyTree(t)
		for _, key := range keys {
			require.NoError(t, tree.pad.Set(key, []byte("value "+key)))
			tree.Update()
		}
		return tree
	}
}

func TestTree_Register(t *testing.T) {
	type args struct {
		key   string
		value []byte
	}
	tests := []struct {
		name     string
		newTree func(*testing.T) *Tree
		args     args
		wantProof merkletree.ProofType
		wantErr  bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := tt.newTree(t)
			gotResp, err := d.Register(tt.args.key, tt.args.value)
			if (err != nil) != tt.wantErr {
				t.Errorf("Register() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			require.NotNil(t, gotResp, "should always get a RegistrationResponse")

			assert.Equal(t, tt.wantProof, gotResp.AuthPath.ProofType())
		})
	}
}