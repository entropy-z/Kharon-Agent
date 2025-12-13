package main

import (
	"bytes"
)

const (
	BlockSize  = 8
	NumRounds  = 16
	XorKeySize = 16
)

type LokyCrypt struct {
	Key    [16]byte
	XorKey [XorKeySize]byte
}

func NewLokyCrypt(key []byte, xorKey []byte) *LokyCrypt {
	var fixedKey [16]byte
	copy(fixedKey[:], key)

	var fixedXor [XorKeySize]byte
	copy(fixedXor[:], xorKey)

	return &LokyCrypt{
		Key:    fixedKey,
		XorKey: fixedXor,
	}
}

func bytesToUint32BE(b []byte) uint32 {
	return (uint32(b[0]) << 24) |
		(uint32(b[1]) << 16) |
		(uint32(b[2]) << 8) |
		uint32(b[3])
}

func uint32ToBytesBE(val uint32) []byte {
	return []byte{
		byte((val >> 24) & 0xFF),
		byte((val >> 16) & 0xFF),
		byte((val >> 8) & 0xFF),
		byte(val & 0xFF),
	}
}

func (lc *LokyCrypt) Cycle(block []byte, encrypt bool) {
	left := bytesToUint32BE(block[0:4])
	right := bytesToUint32BE(block[4:8])

	if encrypt {
		for i := 0; i < NumRounds; i++ {
			tmp := right
			right = left ^ (right + uint32(lc.Key[i%len(lc.Key)]))
			left = tmp
		}
	} else {
		for i := NumRounds - 1; i >= 0; i-- {
			tmp := left
			left = right ^ (left + uint32(lc.Key[i%len(lc.Key)]))
			right = tmp
		}
	}

	copy(block[0:4], uint32ToBytesBE(left))
	copy(block[4:8], uint32ToBytesBE(right))
}

func (lc *LokyCrypt) CalcPadding(length int) int {
	if length%BlockSize == 0 {
		return length + BlockSize
	}
	return length + (BlockSize - (length % BlockSize))
}

func (lc *LokyCrypt) AddPadding(data []byte, length int, total int) []byte {
	padLen := byte(total - length)
	padding := bytes.Repeat([]byte{padLen}, int(padLen))
	return append(data[:length], padding...)
}

func (lc *LokyCrypt) Encrypt(data []byte) []byte {
	length := len(data)
	total := lc.CalcPadding(length)
	padded := lc.AddPadding(data, length, total)

	encrypted := make([]byte, total)
	copy(encrypted, padded)

	for i := 0; i < total; i += BlockSize {
		lc.Cycle(encrypted[i:i+BlockSize], true)
	}
	return encrypted
}

func (lc *LokyCrypt) Decrypt(data []byte) []byte {
	if len(data)%BlockSize != 0 || len(data) == 0 {
		return data
	}

	decrypted := make([]byte, len(data))
	copy(decrypted, data)

	for i := 0; i < len(decrypted); i += BlockSize {
		lc.Cycle(decrypted[i:i+BlockSize], false)
	}

	return lc.RmPadding(decrypted)
}

func (lc *LokyCrypt) RmPadding(data []byte) []byte {
	if len(data) < BlockSize {
		return data
	}

	padLen := int(data[len(data)-1])

	if padLen == 0 || padLen > BlockSize || len(data) < padLen {
		return data
	}

	for i := len(data) - padLen; i < len(data); i++ {
		if data[i] != byte(padLen) {
			return data
		}
	}

	return data[:len(data)-padLen]
}

func (lc *LokyCrypt) Xor(data []byte) {
	for i, j := 0, 0; i < len(data); i++ {
		if j == len(lc.XorKey) {
			j = 0
		}
		if i%2 == 0 {
			data[i] ^= lc.XorKey[j]
		} else {
			data[i] ^= lc.XorKey[j] ^ byte(j)
		}
		j++
	}
}
