package wasmipld

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"testing"

	blocks "github.com/ipfs/go-block-format"
	"github.com/ipfs/go-cid"
	"github.com/ipfs/go-datastore"
	dssync "github.com/ipfs/go-datastore/sync"
	blockstore "github.com/ipfs/go-ipfs-blockstore"
	"github.com/ipld/go-ipld-prime/codec/dagjson"
	"github.com/ipld/go-ipld-prime/datamodel"
	"github.com/ipld/go-ipld-prime/linking"
	cidlink "github.com/ipld/go-ipld-prime/linking/cid"
	basicnode "github.com/ipld/go-ipld-prime/node/basic"
)

func TestBasicCodecAndADL(t *testing.T) {
	//cargo build --target wasm32-unknown-unknown --release
	codecWasm, err := ioutil.ReadFile("../wasmlib/target/wasm32-unknown-unknown/release/bencode.wasm")
	if err != nil {
		panic(err)
	}

	codec, err := NewWasmCodec(codecWasm)
	if err != nil {
		panic(err)
	}

	block, err := ioutil.ReadFile("../wasmlib/bittorrent-fixtures/animals-fixtures/animals.infodict")
	if err != nil {
		panic(err)
	}

	nb := basicnode.Prototype.Any.NewBuilder()
	if err := codec.Decode(nb, bytes.NewReader(block)); err != nil {
		panic(err)
	}
	nd := nb.Build()
	var buf bytes.Buffer
	if err := dagjson.Encode(nd, &buf); err != nil {
		panic(err)
	}
	fmt.Println(buf.String())

	ADLWasm, err := ioutil.ReadFile("../wasmlib/target/wasm32-unknown-unknown/release/bt_dirv1.wasm")
	if err != nil {
		panic(err)
	}

	adl, err := NewWasmADL(ADLWasm)
	if err != nil {
		panic(err)
	}

	ds := dssync.MutexWrap(datastore.NewMapDatastore())
	bs := blockstore.NewBlockstore(ds)

	cidStrs := []string{
		"f01551114dc462b4d35419ca9230d69d758f0832a30959baa",
		"f0155111413da56fd10d288769fdea62d464572c5f16e967d",
	}

	for _, cs := range cidStrs {
		loadedFileBytes, err := ioutil.ReadFile(
			fmt.Sprintf("../wasmlib/bittorrent-fixtures/animals-fixtures/blocks/%s.blk",
				cs,
			))
		if err != nil {
			panic(err)
		}
		c, err := cid.Decode(cs)
		if err != nil {
			panic(err)
		}

		blk, err := blocks.NewBlockWithCid(loadedFileBytes, c)
		if err != nil {
			panic(err)
		}

		if err := bs.Put(context.Background(), blk); err != nil {
			panic(err)
		}
	}

	lsys := cidlink.DefaultLinkSystem()
	lsys.StorageReadOpener = func(lc linking.LinkContext, l datamodel.Link) (io.Reader, error) {
		cl := l.(cidlink.Link)
		blk, err := bs.Get(lc.Ctx, cl.Cid)
		if err != nil {
			return nil, err
		}
		return bytes.NewReader(blk.RawData()), nil
	}

	adlNode, err := adl.Reify(linking.LinkContext{}, nd, &lsys)
	if err != nil {
		panic(err)
	}
	fileNd, err := adlNode.LookupByString("Koala.jpg")
	if err != nil {
		panic(err)
	}
	fileBytes, err := fileNd.AsBytes()
	if err != nil {
		panic(err)
	}

	loadedFileBytes, err := ioutil.ReadFile("../wasmlib/bittorrent-fixtures/animals-fixtures/animals/Koala.jpg")
	if err != nil {
		panic(err)
	}

	if !bytes.Equal(fileBytes, loadedFileBytes) {
		panic("bytes dont match")
	}
}
