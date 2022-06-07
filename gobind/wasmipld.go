package wasmipld

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/bytecodealliance/wasmtime-go"
	"github.com/ipld/go-ipld-prime/linking"

	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/datamodel"
	"github.com/ipld/go-ipld-prime/multicodec"

	mc "github.com/multiformats/go-multicodec"
)

func Register(reg multicodec.Registry) error {
	reg.RegisterEncoder(WacMC, WacEncode)
	reg.RegisterDecoder(WacMC, WacDecode)

	x := &wasmCodec{}
	reg.RegisterDecoder(uint64(mc.Bencode), x.Decode)
	reg.RegisterEncoder(uint64(mc.Bencode), x.Encode)
	return nil
}

func RegisterADL(m map[string]ipld.NodeReifier) error {
	const adlName = "bittorrentv1-file"
	//m[adlName] = bittorrentipld.ReifyBTFile
	m[adlName] = func(context linking.LinkContext, node datamodel.Node, system *linking.LinkSystem) (datamodel.Node, error) {
		x := &wasmADL{}
		return x.Reify(context, node, system)
	}
	return nil
}

const defaultFuelPerOp = 10_000_000

type WasmCodecOption func(*wasmCodec) error

type wasmCodec struct {
	engine *wasmtime.Engine
	module *wasmtime.Module

	fuelPerOp int
}

func NewWasmCodec(wasm []byte, opts ...WasmCodecOption) (*wasmCodec, error) {
	config := wasmtime.NewConfig()
	config.SetConsumeFuel(true)
	engine := wasmtime.NewEngineWithConfig(config)

	// Once we have our binary `wasm` we can compile that into a `*Module`
	// which represents compiled JIT code.
	module, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return nil, err
	}

	ret := &wasmCodec{
		engine:    engine,
		module:    module,
		fuelPerOp: defaultFuelPerOp,
	}

	for _, o := range opts {
		if err := o(ret); err != nil {
			return nil, err
		}
	}
	return ret, nil
}

type WasmCodecOptions struct{}

func (WasmCodecOptions) WithFuelPerOp(fuel int) WasmCodecOption {
	return func(wc *wasmCodec) error {
		wc.fuelPerOp = fuel
		return nil
	}
}

func (c *wasmCodec) Decode(assembler datamodel.NodeAssembler, reader io.Reader) error {
	// Almost all operations in wasmtime require a contextual `store`
	// argument to share, so create that first
	store := wasmtime.NewStore(c.engine)

	// Next up we instantiate a module which is where we link in all our
	// imports. We've got one import so we pass that in here.
	instance, err := wasmtime.NewInstance(store, c.module, []wasmtime.AsExtern{})
	if err != nil {
		return err
	}

	if err := store.AddFuel(uint64(c.fuelPerOp)); err != nil {
		return err
	}

	fn := instance.GetExport(store, "decode").Func()
	memory := instance.GetExport(store, "memory").Memory()
	alloc := instance.GetExport(store, "myalloc").Func()

	block, err := ioutil.ReadAll(reader)
	if err != nil {
		return err
	}

	// // string for alloc
	size := int32(len(block))

	// //Allocate memory
	blockPtrI, err := alloc.Call(store, size)
	if err != nil {
		return err
	}
	blockPtr, _ := blockPtrI.(int32)

	buf := memory.UnsafeData(store)
	copy(buf[blockPtr:], block)

	// Use decode func
	decodePtrI, err := fn.Call(store, blockPtr, size)
	if err != nil {
		return err
	}
	decodePtr, _ := decodePtrI.(int32)
	buf = memory.UnsafeData(store)

	fc, enabled := store.FuelConsumed()
	if !enabled {
		panic("how is fuel consumption not enabled?")
	}
	fmt.Printf("Fuel consumed for block decoding: %d\n", fc)

	valuePtr, err := loadValueOrError(decodePtr, buf)
	if err != nil {
		return err
	}
	wacBytes := loadByteWrapper(buf[valuePtr:], buf)
	return WacDecode(assembler, bytes.NewReader(wacBytes))
}

func (c *wasmCodec) Encode(nd datamodel.Node, w io.Writer) error {
	var wacbuf bytes.Buffer
	if err := WacEncode(nd, &wacbuf); err != nil {
		return err
	}

	// Almost all operations in wasmtime require a contextual `store`
	// argument to share, so create that first
	store := wasmtime.NewStore(c.engine)

	// Next up we instantiate a module which is where we link in all our
	// imports. We've got one import so we pass that in here.
	instance, err := wasmtime.NewInstance(store, c.module, []wasmtime.AsExtern{})
	if err != nil {
		return err
	}

	if err := store.AddFuel(uint64(c.fuelPerOp)); err != nil {
		return err
	}

	fn := instance.GetExport(store, "encode").Func()
	memory := instance.GetExport(store, "memory").Memory()
	alloc := instance.GetExport(store, "myalloc").Func()

	block := wacbuf.Bytes()
	// // string for alloc
	size := int32(len(block))

	// //Allocate memory
	blockPtrI, err := alloc.Call(store, size)
	if err != nil {
		return err
	}
	blockPtr, _ := blockPtrI.(int32)

	buf := memory.UnsafeData(store)
	copy(buf[blockPtr:], block)

	// Use encode func
	encodePtrI, err := fn.Call(store, blockPtr, size)
	if err != nil {
		return err
	}
	encodePtr, _ := encodePtrI.(int32)
	buf = memory.UnsafeData(store)

	fc, enabled := store.FuelConsumed()
	if !enabled {
		panic("how is fuel consumption not enabled?")
	}
	fmt.Printf("Fuel consumed for block encoding: %d\n", fc)

	valuePtr, err := loadValueOrError(encodePtr, buf)
	if err != nil {
		return err
	}
	blockBytes := loadByteWrapper(buf[valuePtr:], buf)
	if _, err := w.Write(blockBytes); err != nil {
		return err
	}

	return nil
}
