// Copyright 2015 The Coname Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License.  You may obtain a copy
// of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
// License for the specific language governing permissions and limitations
// under the License.

package conv

// ToBytes converts a slice of bits into
// a slice of bytes.
// In each byte, the bits are ordered MSB to LSB.
func ToBytes(bits []bool) []byte {
	bs := make([]byte, (len(bits)+7)/8)
	for i := 0; i < len(bits); i++ {
		if bits[i] {
			bs[i/8] |= (1 << 7) >> uint(i%8)
		}
	}
	return bs
}

// ToBits converts a slice of bytes into
// a slice of bits.
// In each byte, the bits are ordered MSB to LSB.
func ToBits(bs []byte) []bool {
	bits := make([]bool, len(bs)*8)
	for i := 0; i < len(bits); i++ {
		bits[i] = (bs[i/8]<<uint(i%8))&(1<<7) > 0
	}
	return bits
}