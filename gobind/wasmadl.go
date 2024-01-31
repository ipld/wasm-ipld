package wasmipld

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/bytecodealliance/wasmtime-go"
	"github.com/ipfs/go-cid"
	"github.com/ipld/go-ipld-prime"
	"github.com/ipld/go-ipld-prime/datamodel"
	"github.com/ipld/go-ipld-prime/linking"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	basicnode "github.com/ipld/go-ipld-prime/node/basic"
)

type WasmADLOption func(*wasmADL) error

type wasmADL struct {
	engine *wasmtime.Engine
	module *wasmtime.Module

	fuelPerOp int
}

// NewWasmADL creates a WASM based IPLD ADL from the WASM code
func NewWasmADL(wasm []byte, opts ...WasmADLOption) (*wasmADL, error) {
	config := wasmtime.NewConfig()
	config.SetConsumeFuel(true)
	engine := wasmtime.NewEngineWithConfig(config)

	// Once we have our binary `wasm` we can compile that into a `*Module`
	// which represents compiled JIT code.
	module, err := wasmtime.NewModule(engine, wasm)
	if err != nil {
		return nil, err
	}

	ret := &wasmADL{
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

type WasmADLOptions struct{}

func (WasmADLOptions) WithFuelPerOp(fuel int) WasmADLOption {
	return func(wa *wasmADL) error {
		wa.fuelPerOp = fuel
		return nil
	}
}

func (a *wasmADL) Reify(ctx linking.LinkContext, node datamodel.Node, lsys *linking.LinkSystem) (datamodel.Node, error) {
	n := &wasmADLNode{
		ctx:      ctx,
		lsys:     lsys,
		basewasm: a,
	}
	if err := n.initialize(node); err != nil {
		return nil, err
	}
	return n, nil
}

type wasmADLNode struct {
	ctx  linking.LinkContext
	lsys *ipld.LinkSystem

	basewasm *wasmADL

	k datamodel.Kind

	w          *wasmtimeThings
	adlWasmPtr int32
}

var _ datamodel.LargeBytesNode = (*wasmADLNode)(nil)

// TODO: globals, caching, etc.
type wasmtimeThings struct {
	store    *wasmtime.Store
	instance *wasmtime.Instance
	tfc      uint64

	basewasm *wasmADL
}

// initialize sets up the WASM environment for the ADL as well as loading the ADL itself
func (w *wasmADLNode) initialize(substrate ipld.Node) error {
	// Almost all operations in wasmtime require a contextual `store`
	// argument to share, so create that first
	store := wasmtime.NewStore(w.basewasm.engine)

	if err := store.AddFuel(uint64(w.basewasm.fuelPerOp)); err != nil {
		return err
	}

	blockLoadRespFn := func(caller *wasmtime.Caller, cidPtr int32, cidLen int32, blockFn func(cid.Cid) ([]byte, error)) int32 {
		memory := caller.GetExport("memory").Memory()
		buf := memory.UnsafeData(store)
		_, c, err := cid.CidFromBytes(buf[cidPtr : cidPtr+cidLen])
		if err != nil {
			return 0
		}
		alloc := caller.GetExport("myalloc").Func()
		allocFn := func(size int32) (int32, []byte, error) {
			inputBlkPtrI, err := alloc.Call(caller, size)
			if err != nil {
				return 0, nil, err
			}

			inputBlkPtr, ok := inputBlkPtrI.(int32)
			if !ok {
				return 0, nil, fmt.Errorf("alloc did not return int32")
			}

			buf := memory.UnsafeData(store)
			buf = buf[inputBlkPtr : inputBlkPtr+size]
			return inputBlkPtr, buf, nil
		}

		blk, err := blockFn(c)
		if err != nil {
			ptr, err := createBlockResp([]byte(err.Error()), true, allocFn)
			if err != nil {
				// TODO: trigger a trap
				log.Println("error creating a block response")
			}
			return ptr
		}

		ptr, err := createBlockResp([]byte(blk), false, allocFn)
		if err != nil {
			// TODO: trigger a trap
			log.Println("error creating a block response")
		}
		return ptr

	}

	// function for if WASM asks for a raw block
	loadBlockFn := wasmtime.WrapFunc(store, func(caller *wasmtime.Caller, cidPtr int32, cidLen int32) int32 {
		return blockLoadRespFn(caller, cidPtr, cidLen, func(c cid.Cid) ([]byte, error) {
			return w.lsys.LoadRaw(w.ctx, cidlink.Link{Cid: c})
		})
	})

	// function for if WASM asks for a WAC encoded block
	loadWACFn := wasmtime.WrapFunc(store, func(caller *wasmtime.Caller, cidPtr int32, cidLen int32) int32 {
		return blockLoadRespFn(caller, cidPtr, cidLen, func(c cid.Cid) ([]byte, error) {
			nd, err := w.lsys.Load(w.ctx, cidlink.Link{Cid: c}, basicnode.Prototype.Any)
			if err != nil {
				return nil, err
			}
			var buf bytes.Buffer
			if err := WacEncode(nd, &buf); err != nil {
				return nil, err
			}
			return buf.Bytes(), nil
		})
	})

	// Next up we instantiate a module which is where we link in all our
	// imports. We've got one import so we pass that in here.
	instance, err := wasmtime.NewInstance(store, w.basewasm.module, []wasmtime.AsExtern{loadBlockFn, loadWACFn})
	if err != nil {
		return err
	}

	w.w = &wasmtimeThings{
		store:    store,
		instance: instance,
		basewasm: w.basewasm,
	}

	loadAdlFn := instance.GetExport(store, "load_adl").Func()
	memory := instance.GetExport(store, "memory").Memory()
	alloc := instance.GetExport(store, "myalloc").Func()

	var inputBuf bytes.Buffer

	// encode the node into WAC so it can be loaded and processed in WASM
	if err := WacEncode(substrate, &inputBuf); err != nil {
		return err
	}

	// Allocate memory
	inputSize := int32(inputBuf.Len())
	inputBlkPtrI, err := alloc.Call(store, inputSize)
	if err != nil {
		return err
	}
	inputBlkPtr, ok := inputBlkPtrI.(int32)
	if !ok {
		return fmt.Errorf("input block pointer not int32")
	}
	input := inputBuf.Bytes()

	// TODO: Dellocate input buffer

	// Copy WAC encoded ADL root node into WASM
	buf := memory.UnsafeData(store)
	copy(buf[inputBlkPtr:], input)

	// Load the ADL
	retPtrI, err := loadAdlFn.Call(store, inputBlkPtr, inputSize)
	if err != nil {
		return err
	}
	retPtr, ok := retPtrI.(int32)
	if !ok {
		return fmt.Errorf("adl pointer not int32")
	}

	buf = memory.UnsafeData(store)
	adlPtr, adlKind, wacBuf, err := loadADLorWAC(retPtr, buf)
	if err != nil {
		return err
	}

	// If a pointer to manage the ADL was returned set it up
	if adlPtr != 0 {
		w.adlWasmPtr = int32(adlPtr)
		w.k = adlKind.ToDataModelKind()
		if w.k == datamodel.Kind_Invalid {
			return fmt.Errorf("invalid datamodel kind for adl")
		}
	} else if len(wacBuf) != 0 {
		// TODO: If WAC data was returned (e.g. simple ADLs like a fancy type of BigInt might want to use something like this)
		return fmt.Errorf("returning WAC during ADL initialization is unsupported")
	}

	tfc, enabled := store.FuelConsumed()
	if !enabled {
		panic("how is fuel consumption not enabled?")
	}
	fc := tfc - w.w.tfc
	w.w.tfc = tfc
	fmt.Printf("Fuel consumed for ADL load: %d\n", fc)
	if err := store.AddFuel(uint64(w.basewasm.fuelPerOp) - fc); err != nil {
		return err
	}

	return nil
}

func (w *wasmADLNode) Kind() datamodel.Kind {
	return w.k
}

func (w *wasmADLNode) LookupByString(key string) (datamodel.Node, error) {
	alloc := w.w.instance.GetExport(w.w.store, "myalloc").Func()
	getKeyFn := w.w.instance.GetExport(w.w.store, "get_key").Func()

	// Allocate memory
	bufferPtrI, err := alloc.Call(w.w.store, len(key))
	if err != nil {
		return nil, err
	}
	bufferPtr, ok := bufferPtrI.(int32)
	if !ok {
		return nil, fmt.Errorf("buffer pointer not int32")
	}

	// TODO: Dellocate input buffer
	// copy the key bytes into WASM
	memory := w.w.instance.GetExport(w.w.store, "memory").Memory()
	buf := memory.UnsafeData(w.w.store)
	copy(buf[bufferPtr:], []byte(key))

	// Call the lookup
	getKeyRespPtrI, err := getKeyFn.Call(w.w.store, w.adlWasmPtr, bufferPtr, int32(len(key)))

	tfc, enabled := w.w.store.FuelConsumed()
	if !enabled {
		panic("how is fuel consumption not enabled?")
	}
	fc := tfc - w.w.tfc
	w.w.tfc = tfc
	fmt.Printf("Fuel consumed for key lookup: %d\n", fc)
	if err := w.w.store.AddFuel(uint64(w.w.basewasm.fuelPerOp) - fc); err != nil {
		return nil, err
	}

	// Only check the error from the lookup after we've adjusted the fuel
	if err != nil {
		return nil, err
	}
	getKeyRespPtr, ok := getKeyRespPtrI.(int32)
	if !ok {
		return nil, fmt.Errorf("ptr type not int32")
	}

	buf = memory.UnsafeData(w.w.store)

	// Check the response
	adlPtr, adlKind, wacBytes, err := loadADLorWAC(getKeyRespPtr, buf)
	if err != nil {
		return nil, err
	}

	// If the returned data was WAC encoded just decode and return it
	if wacBytes != nil {
		nb := basicnode.Prototype.Any.NewBuilder()
		if err := WacDecode(nb, bytes.NewReader(wacBytes)); err != nil {
			return nil, err
		}
		return nb.Build(), nil
	}

	if adlPtr == 0 {
		return nil, fmt.Errorf("no data returned")
	}

	// Otherwise return a node that is based on a WASM pointer
	newNode := &wasmADLNode{
		ctx:        w.ctx,
		lsys:       w.lsys,
		basewasm:   w.basewasm,
		k:          adlKind.ToDataModelKind(),
		w:          w.w,
		adlWasmPtr: int32(adlPtr),
	}
	if newNode.k == datamodel.Kind_Invalid {
		return nil, fmt.Errorf("invalid datamodel kind for ADL")
	}

	return newNode, nil
}

func (w *wasmADLNode) LookupByNode(key datamodel.Node) (datamodel.Node, error) {
	ks, err := key.AsString()
	if err != nil {
		return nil, err
	}
	return w.LookupByString(ks)
}

func (w *wasmADLNode) LookupByIndex(idx int64) (datamodel.Node, error) {
	panic("implement me")
}

func (w *wasmADLNode) LookupBySegment(seg datamodel.PathSegment) (datamodel.Node, error) {
	return w.LookupByString(seg.String())
}

func (w *wasmADLNode) MapIterator() datamodel.MapIterator {
	if w.k != datamodel.Kind_Map {
		return nil
	}
	panic("implement me")
}

func (w *wasmADLNode) ListIterator() datamodel.ListIterator {
	if w.k != datamodel.Kind_List {
		return nil
	}
	panic("implement me")
}

func (w *wasmADLNode) Length() int64 {
	panic("implement me")
}

func (w *wasmADLNode) IsAbsent() bool {
	// TODO: What should go here?
	return false
}

func (w *wasmADLNode) IsNull() bool {
	// TODO: Is this right?
	return w.k == datamodel.Kind_Null
}

func (w *wasmADLNode) AsBool() (bool, error) {
	if w.k != datamodel.Kind_Link {
		return false, ipld.ErrWrongKind{TypeName: "bool", MethodName: "AsBool", AppropriateKind: datamodel.KindSet{w.k}}
	}
	panic("implement me")
}

func (w *wasmADLNode) AsInt() (int64, error) {
	if w.k != datamodel.Kind_Link {
		return 0, ipld.ErrWrongKind{TypeName: "int", MethodName: "AsInt", AppropriateKind: datamodel.KindSet{w.k}}
	}
	panic("implement me")
}

func (w *wasmADLNode) AsFloat() (float64, error) {
	if w.k != datamodel.Kind_Link {
		return 0, ipld.ErrWrongKind{TypeName: "float", MethodName: "AsFloat", AppropriateKind: datamodel.KindSet{w.k}}
	}
	panic("implement me")
}

func (w *wasmADLNode) AsString() (string, error) {
	if w.k != datamodel.Kind_Link {
		return "", ipld.ErrWrongKind{TypeName: "string", MethodName: "AsString", AppropriateKind: datamodel.KindSet{w.k}}
	}
	panic("implement me")
}

func (w *wasmADLNode) AsBytes() ([]byte, error) {
	rdr, err := w.AsLargeBytes()
	if err != nil {
		return nil, err
	}
	return io.ReadAll(rdr)
}

func (w *wasmADLNode) AsLink() (datamodel.Link, error) {
	if w.k != datamodel.Kind_Link {
		return nil, ipld.ErrWrongKind{TypeName: "link", MethodName: "AsLink", AppropriateKind: datamodel.KindSet{w.k}}
	}
	panic("implement me")
}

func (w *wasmADLNode) Prototype() datamodel.NodePrototype {
	return nil
}

func (w *wasmADLNode) AsLargeBytes() (io.ReadSeeker, error) {
	if w.k != datamodel.Kind_Bytes {
		return nil, ipld.ErrWrongKind{TypeName: "bytes", MethodName: "AsLargeBytes", AppropriateKind: datamodel.KindSet{w.k}}
	}

	newReaderFn := w.w.instance.GetExport(w.w.store, "new_bytes_reader").Func()

	// Create a new WASM reader that can be used for ReaderSeeker behavior
	newReaderPtrI, err := newReaderFn.Call(w.w.store, w.adlWasmPtr)
	if err != nil {
		return nil, err
	}
	readerPtr, ok := newReaderPtrI.(int32)
	if !ok {
		return nil, fmt.Errorf("reader pointer not int32")
	}

	return &wasmADLRS{
		wt:     w.w,
		adlPtr: readerPtr,
	}, nil
}

type wasmADLRS struct {
	wt     *wasmtimeThings
	adlPtr int32
}

func (r *wasmADLRS) Read(p []byte) (n int, err error) {
	alloc := r.wt.instance.GetExport(r.wt.store, "myalloc").Func()
	readFn := r.wt.instance.GetExport(r.wt.store, "read_adl").Func()

	// Allocate memory for read responses
	bufferPtrI, err := alloc.Call(r.wt.store, len(p))
	if err != nil {
		return 0, err
	}
	bufferPtr, ok := bufferPtrI.(int32)
	if !ok {
		return 0, fmt.Errorf("buffer pointer not int32")
	}

	// Read into the buffer
	readRespPtrI, err := readFn.Call(r.wt.store, r.adlPtr, bufferPtr, int32(len(p)))

	tfc, enabled := r.wt.store.FuelConsumed()
	if !enabled {
		panic("how is fuel consumption not enabled?")
	}
	fc := tfc - r.wt.tfc
	r.wt.tfc = tfc
	fmt.Printf("Fuel consumed for read: %d\n", fc)
	if err := r.wt.store.AddFuel(uint64(r.wt.basewasm.fuelPerOp) - fc); err != nil {
		return 0, err
	}

	// Don't error on the read until after fuel has been adjusted
	if err != nil {
		return 0, err
	}
	readRespPtr, ok := readRespPtrI.(int32)
	if !ok {
		return 0, fmt.Errorf("read type not int32")
	}

	// TODO: Dellocate input buffer
	memory := r.wt.instance.GetExport(r.wt.store, "memory").Memory()

	// Check if there was an error
	buf := memory.UnsafeData(r.wt.store)
	numReturned, err := loadReadResp(readRespPtr, buf)
	numRet := int(numReturned)
	if numRet < 0 {
		return 0, fmt.Errorf("read return underflow")
	}

	// If data was read copy it into our output buffer and return how many bytes we read
	if numRet > 0 {
		copy(p, buf[bufferPtr:bufferPtr+int32(numRet)])
	}

	return int(numRet), err
}

func (r *wasmADLRS) Seek(offset int64, whence int) (int64, error) {
	seekFn := r.wt.instance.GetExport(r.wt.store, "seek_adl").Func()
	resI, err := seekFn.Call(r.wt.store, r.adlPtr, offset, int32(whence))

	tfc, enabled := r.wt.store.FuelConsumed()
	if !enabled {
		panic("how is fuel consumption not enabled?")
	}
	fc := tfc - r.wt.tfc
	r.wt.tfc = tfc
	fmt.Printf("Fuel consumed for seek: %d\n", fc)
	if err := r.wt.store.AddFuel(uint64(r.wt.basewasm.fuelPerOp) - fc); err != nil {
		return 0, err
	}

	// Don't error until fuel has been adjusted
	if err != nil {
		return 0, err
	}
	res, ok := resI.(int64)
	if !ok {
		return 0, fmt.Errorf("returned seek offset not a int64")
	}
	return res, nil
}

var _ io.ReadSeeker = (*wasmADLRS)(nil)
