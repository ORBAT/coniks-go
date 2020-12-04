package conv

import (
	"unsafe"
)

// GetNthBit finds the bit in the byte array bs
// at offset, and determines whether it is 1 or 0.
// It returns true if the nth bit is 1, false otherwise.
func GetNthBit(bs []byte, offset uint32) bool {
	arrayOffset := offset / 8
	bitOfByte := offset % 8

	masked := int(bs[arrayOffset] & (1 << uint(7-bitOfByte)))
	return masked != 0
}


// LongToBytes converts an int64 variable to byte array
// in the native endianness of the current platform.
func LongToBytes(num int64) []byte {
	// - take a pointer to num
	// - turn it into an unsafe.Pointer
	// - turn the unsafe.Pointer into a *[8]byte, i.e. a pointer to the bytes of num but in an array
	// - dereference *[8]byte to give us a [8]byte
	array := *(*[8]byte)(unsafe.Pointer(&num))
	return array[:]
}

// ULongToBytes converts an uint64 variable to byte array
// in the native endianness of the current platform.
func ULongToBytes(num uint64) []byte {
	return LongToBytes(int64(num))
}

// UInt32ToBytes converts an uint32 variable to byte array
// in the native endianness of the current platform.
func UInt32ToBytes(num uint32) []byte {
	// - take a pointer to num
	// - turn it into an unsafe.Pointer
	// - turn the unsafe.Pointer into a *[4]byte, i.e. a pointer to the bytes of num but in an array
	// - dereference *[4]byte to give us a [4]bytes
	array := *(*[4]byte)(unsafe.Pointer(&num))
	return array[:]
}