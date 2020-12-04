package directory

import (
	"testing"

	"github.com/ORBAT/cloniks/protocol"
)

func TestPoliciesChanges(t *testing.T) {
	d := NewTestTree(t)
	if p := d.LatestSTR().Policies.UpdateInterval; p != 1 {
		t.Fatal("Unexpected policies", "want", 1, "got", p)
	}

	// change the policies
	d.SetPolicies(2)
	d.Update()
	// expect the policies doesn't change yet
	if p := d.LatestSTR().Policies.UpdateInterval; p != 1 {
		t.Fatal("Unexpected policies", "want", 1, "got", p)
	}

	d.Update()
	// expect the new policies
	if p := d.LatestSTR().Policies.UpdateInterval; p != 2 {
		t.Fatal("Unexpected policies", "want", 2, "got", p)
	}

	p0 := GetConfig(d.pad.GetSTR(0)).UpdateInterval
	p1 := GetConfig(d.pad.GetSTR(1)).UpdateInterval
	p2 := GetConfig(d.pad.GetSTR(2)).UpdateInterval
	if p0 != 1 || p1 != 1 || p2 != 2 {
		t.Fatal("Maybe the STR's policies were malformed")
	}
}

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
