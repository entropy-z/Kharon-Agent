package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type Packer struct {
	buffer []byte
}

func CreatePacker(buffer []byte) *Packer {
	return &Packer{
		buffer: buffer,
	}
}

func (p *Packer) Size() uint {
	return uint(len(p.buffer))
}

func (p *Packer) CheckPacker(types []string) bool {

	packerSize := p.Size()

	for _, t := range types {
		switch t {

		case "byte":
			if packerSize < 1 {
				return false
			}
			packerSize -= 1

		case "word":
			if packerSize < 2 {
				return false
			}
			packerSize -= 2

		case "int":
			if packerSize < 4 {
				return false
			}
			packerSize -= 4

		case "long":
			if packerSize < 8 {
				return false
			}
			packerSize -= 8

		case "array":
			if packerSize < 4 {
				return false
			}

			index := p.Size() - packerSize
			value := make([]byte, 4)
			copy(value, p.buffer[index:index+4])
			length := uint(binary.BigEndian.Uint32(value))
			packerSize -= 4

			if packerSize < length {
				return false
			}
			packerSize -= length
		}
	}
	return true
}

func (p *Packer) ParseInt8() uint8 {
	var value = make([]byte, 1)

	if p.Size() >= 1 {
		if p.Size() == 1 {
			copy(value, p.buffer[:p.Size()])
			p.buffer = []byte{}
		} else {
			copy(value, p.buffer[:1])
			p.buffer = p.buffer[1:]
		}
	} else {
		return 0
	}

	return value[0]
}

func (p *Packer) ParseInt16() uint16 {
	var value = make([]byte, 2)

	if p.Size() >= 2 {
		if p.Size() == 2 {
			copy(value, p.buffer[:p.Size()])
			p.buffer = []byte{}
		} else {
			copy(value, p.buffer[:2])
			p.buffer = p.buffer[2:]
		}
	} else {
		return 0
	}

	return binary.BigEndian.Uint16(value)
}

func (p *Packer) ParseInt32() uint {
	var value = make([]byte, 4)

	if p.Size() >= 4 {
		if p.Size() == 4 {
			copy(value, p.buffer[:p.Size()])
			p.buffer = []byte{}
		} else {
			copy(value, p.buffer[:4])
			p.buffer = p.buffer[4:]
		}
	} else {
		return 0
	}

	return uint(binary.BigEndian.Uint32(value))
}

func (p *Packer) ParseInt64() uint64 {
	var value = make([]byte, 8)

	if p.Size() >= 8 {
		if p.Size() == 8 {
			copy(value, p.buffer[:p.Size()])
			p.buffer = []byte{}
		} else {
			copy(value, p.buffer[:8])
			p.buffer = p.buffer[8:]
		}
	} else {
		return 0
	}

	return binary.BigEndian.Uint64(value)
}

func (p *Packer) ParsePad(size uint) []byte {
	if p.Size() < size {
		return make([]byte, 0)
	} else {
		b := p.buffer[:size]
		p.buffer = p.buffer[size:]
		return b
	}
}

func (p *Packer) ParseBytes() []byte {
	size := p.ParseInt32()

	if p.Size() < size {
		return make([]byte, 0)
	} else {
		b := p.buffer[:size]
		p.buffer = p.buffer[size:]
		return b
	}
}

func (p *Packer) ParseString() string {
	size := p.ParseInt32()

	if p.Size() < size {
		return ""
	} else {
		b := p.buffer[:size]
		p.buffer = p.buffer[size:]
		return string(bytes.Trim(b, "\x00"))
	}
}

func PackArray(array []interface{}) ([]byte, error) {
	var packData []byte
	//fmt.printf("=== PACK ARRAY START ===\n")
	//fmt.printf("Elements: %d\n", len(array))

	for i := range array {
		//fmt.printf("[Elem %d]: ", i)

		switch v := array[i].(type) {

		case []byte:
			val := array[i].([]byte)
			packData = append(packData, val...)
			//fmt.printf("[%d bytes]", len(val))

		case string:
			size := make([]byte, 4)
			val := array[i].(string)
			if len(val) != 0 {
				if !strings.HasSuffix(val, "\x00") {
					val += "\x00"
				}
			}
			binary.LittleEndian.PutUint32(size, uint32(len(val)))
			packData = append(packData, size...)
			packData = append(packData, []byte(val)...)
			//fmt.printf("[4 bytes size][%d bytes data]", len(val))

		case []uint16: 
			size := make([]byte, 4)
			
			needsTerminator := true
			if len(v) > 0 && v[len(v)-1] == 0 {
				needsTerminator = false
			}
			
			totalSize := len(v) * 2
			if needsTerminator {
				totalSize += 2 
			}
			
			val := make([]byte, totalSize)
			
			for i, wchar := range v {
				val[i*2] = byte(wchar)
				val[i*2+1] = byte(wchar >> 8)
			}
			
			if needsTerminator && len(v) > 0 {
				val[len(v)*2] = 0x00
				val[len(v)*2+1] = 0x00
			}

			fmt.Printf("out %s\n", val)
			
			binary.LittleEndian.PutUint32(size, uint32(len(val)))
			packData = append(packData, size...)
			packData = append(packData, val...)

		case int:
			num := make([]byte, 4)
			val := array[i].(int)
			binary.LittleEndian.PutUint32(num, uint32(val))
			packData = append(packData, num...)
			//fmt.printf("[4 bytes]: %d", val)

		case int16:
			num := make([]byte, 2)
			val := array[i].(int16)
			binary.LittleEndian.PutUint16(num, uint16(val))
			packData = append(packData, num...)
			//fmt.printf("[2 bytes]: %d", val)

		case int8:
			num := make([]byte, 1)
			num[0] = byte(array[i].(int8))
			packData = append(packData, num...)
			//fmt.printf("[1 byte]: %d", num)

		case bool:
			var bt = make([]byte, 1)
			if array[i].(bool) {
				bt[0] = 1
			}
			packData = append(packData, bt...)
			//fmt.printf("[1 byte]: %d", bt)

		default:
			//fmt.printf("[ERROR: unknown type]")
			return nil, errors.New("PackArray unknown type")
		}

		//fmt.printf(" → Total: %d bytes\n", len(packData))
	}

	//fmt.printf("=== PACK ARRAY END ===\n")
	//fmt.printf("Final size: %d bytes\n", len(packData))
	//fmt.printf("Final structure complete\n")
	return packData, nil
}
