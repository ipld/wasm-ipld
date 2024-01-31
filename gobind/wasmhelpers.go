package wasmipld

/*
#include <stdint.h>
#include <stdbool.h>
struct ByteWrapper {
	uint32_t msg_len;
	uint32_t msg_ptr;
};

struct ValueOrError {
	uint32_t bw_ptr;
	uint32_t val_ptr;
};

struct ADLorWAC {
	uint32_t err_bw_ptr;
	uint32_t adl_ptr;
	uint8_t adl_kind;
	uint32_t wac_bw_ptr;
};

struct IterResp {
	uint32_t err_bw_ptr;
	uint32_t key_bw_ptr;
	uint32_t value_adl_ptr;
	uint8_t value_adl_kind;
	uint32_t wac_bw_ptr;
};

struct ReadResp {
	uint32_t err_bw_ptr;
	uint32_t bytes_read;
};

struct BoolOrError {
    uint32_t err_bw_ptr;
    bool value;
};

struct BlockResp {
    uint32_t msg_len;
    uint32_t msg_ptr;
    bool is_err;
};
*/
import "C"

import (
	"fmt"
	"io"
	"unsafe"
)

// loadByteWrapper decodes the ByteWrapper to bytes
func loadByteWrapper(data []byte, backingBuffer []byte) []byte {
	var foo unsafe.Pointer = C.CBytes(data[:C.sizeof_struct_ByteWrapper])
	x := *(*C.struct_ByteWrapper)(foo)
	ptr := uint32(x.msg_ptr)
	length := uint32(x.msg_len)
	return backingBuffer[ptr : ptr+length]
}

type wasmPointer uint32

// loadValueOrError returns a pointer to some WASM data or an error
func loadValueOrError(dataPtr int32, backingBuffer []byte) (wasmPointer, error) {
	var foo unsafe.Pointer = C.CBytes(backingBuffer[dataPtr : dataPtr+C.sizeof_struct_ValueOrError])
	x := *(*C.struct_ValueOrError)(foo)
	errPtr := uint32(x.bw_ptr)
	valPtr := uint32(x.val_ptr)

	if errPtr != 0 {
		err := fmt.Errorf(string(loadByteWrapper(backingBuffer[errPtr:], backingBuffer)))
		return 0, err
	}

	if valPtr == 0 {
		return 0, fmt.Errorf("all fields null")
	}

	return wasmPointer(valPtr), nil
}

// loadADLorWAC returns either a pointer to an ADL in WASM along with its kind,  WAC encoded data, or an error.
// The kind is an integer whose values happen to match the ones from WAC.
func loadADLorWAC(dataPtr int32, backingBuffer []byte) (wasmPointer, WacCode, []byte, error) {
	var cptr unsafe.Pointer = C.CBytes(backingBuffer[dataPtr : dataPtr+C.sizeof_struct_ADLorWAC])
	structData := *(*C.struct_ADLorWAC)(cptr)
	errPtr := uint32(structData.err_bw_ptr)
	adlPtr := uint32(structData.adl_ptr)
	adlKind := uint8(structData.adl_kind)
	wacPtr := uint32(structData.wac_bw_ptr)

	if errPtr != 0 {
		err := fmt.Errorf(string(loadByteWrapper(backingBuffer[errPtr:], backingBuffer)))
		return 0, 0, nil, err
	}

	if adlPtr != 0 {
		return wasmPointer(adlPtr), WacCode(adlKind), nil, nil
	}

	if wacPtr == 0 {
		return 0, 0, nil, fmt.Errorf("all fields null")
	}

	return 0, 0, loadByteWrapper(backingBuffer[wacPtr:], backingBuffer), nil
}

// loadIterResp returns either a pointer to an ADL in WASM along with its kind,  WAC encoded data, or an error.
// The kind is an integer whose values happen to match the ones from WAC.
func loadIterResp(data, backingBuffer []byte) (string, wasmPointer, WacCode, []byte, error) {
	var cptr unsafe.Pointer = C.CBytes(data[:C.sizeof_struct_IterResp])
	structData := *(*C.struct_IterResp)(cptr)

	errPtr := uint32(structData.err_bw_ptr)
	keyPtr := uint32(structData.key_bw_ptr)
	adlPtr := uint32(structData.value_adl_ptr)
	adlKind := uint32(structData.value_adl_kind)
	wacPtr := uint32(structData.wac_bw_ptr)

	if errPtr != 0 {
		err := fmt.Errorf(string(loadByteWrapper(backingBuffer[errPtr:], backingBuffer)))
		return "", 0, 0, nil, err
	}

	if keyPtr == 0 {
		return "", 0, 0, nil, fmt.Errorf("key is null")
	}
	key := string(loadByteWrapper(backingBuffer[keyPtr:], backingBuffer))

	if adlPtr != 0 {
		return key, wasmPointer(adlPtr), WacCode(adlKind), nil, nil
	}

	if wacPtr == 0 {
		return "", 0, 0, nil, fmt.Errorf("all fields null")
	}

	return key, 0, 0, loadByteWrapper(backingBuffer[wacPtr:], backingBuffer), nil
}

// loadReadResp returns the number of bytes read or an error
func loadReadResp(dataPtr int32, backingBuffer []byte) (uint32, error) {
	var cptr unsafe.Pointer = C.CBytes(backingBuffer[dataPtr : dataPtr+C.sizeof_struct_ReadResp])
	structData := *(*C.struct_ReadResp)(cptr)

	errPtr := uint32(structData.err_bw_ptr)
	bytesRead := uint32(structData.bytes_read)

	if errPtr != 0 {
		errStr := string(loadByteWrapper(backingBuffer[errPtr:], backingBuffer))
		if errStr == "read: EOF" {
			return 0, io.EOF
		}
		err := fmt.Errorf(errStr)
		return 0, err
	}

	return bytesRead, nil
}

// createBlockResp takes either block data or an error message and allocates it in WASM
// returning the pointer for where the response lives or an error.
func createBlockResp(data []byte, isErr bool, alloc func(int32) (int32, []byte, error)) (int32, error) {
	var dataVal C.struct_BlockResp
	dataVal.msg_len = C.uint(len(data))
	dataVal.is_err = isErr == true

	ptr, buf, err := alloc(int32(len(data)) + C.sizeof_struct_BlockResp)
	if err != nil {
		return 0, err
	}
	dataPtr := ptr + C.sizeof_struct_BlockResp
	dataVal.msg_ptr = C.uint(dataPtr)

	respAsArr := *(*[C.sizeof_struct_BlockResp]byte)(unsafe.Pointer(&dataVal))
	copy(buf[:C.sizeof_struct_BlockResp], respAsArr[:])
	copy(buf[C.sizeof_struct_BlockResp:], []byte(data))

	return ptr, nil
}
