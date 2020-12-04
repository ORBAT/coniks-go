package directory

// A TemporaryBinding consists of the private Index for a key, its Value, and a digital Signature of
// these fields.
//
// A TB serves as a proof of registration and as a signed promise by a server to include the
// corresponding name-to-key binding in the next directory snapshot. As such, TBs allow clients to
// begin using the contained key-to-value binding without having to wait for the binding's inclusion
// in the next snapshot.
type TemporaryBinding struct {
	Index     []byte
	Value     []byte
	Signature []byte
}

// Bytes serializes the temporary binding into
// a specified format.
func (tb *TemporaryBinding) Bytes(strSig []byte) []byte {
	tbBytes := make([]byte, 0, len(strSig) + len(tb.Index) + len(tb.Value))
	tbBytes = append(tbBytes, strSig...)
	tbBytes = append(tbBytes, tb.Index...)
	tbBytes = append(tbBytes, tb.Value...)
	return tbBytes
}
