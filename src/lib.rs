use std::{collections::BTreeMap, intrinsics::{copy_nonoverlapping, transmute}, convert::TryInto, fs::File, io::Read, borrow::BorrowMut};

use libipld::{codec::Codec, ipld, error::Error, Multihash, cid::CidGeneric, Cid};

mod bencode;
mod wac;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
//#[cfg(feature = "wee_alloc")]
//#[global_allocator]
//static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Allocate memory into the module's linear memory
/// and return the offset to the start of the block.
#[no_mangle]
pub fn myalloc(len: usize) -> *mut u8 {
    // create a new mutable buffer with capacity `len`
    let mut buf = Vec::with_capacity(len);
    // take a mutable pointer to the buffer
    let ptr = buf.as_mut_ptr();
    // take ownership of the memory block and
    // ensure that its destructor is not
    // called when the object goes out of scope
    // at the end of the function
    std::mem::forget(buf);
    // return the pointer so the runtime
    // can write data at this offset
    return ptr;
}

/// Given a pointer to the start of a byte array and
/// its length, decode it into a standard IPLD codec representation
/// (for now DAG-CBOR)
#[no_mangle]
pub unsafe fn decode(ptr: *mut u8, len: usize, out_len : &mut u32) -> *const u8 {
    pattern(ptr, len, out_len, decode_block)
}

unsafe fn pattern(ptr: *mut u8, len: usize, out_len : &mut u32, func : fn(input: Vec<u8>, out_len : &mut u32) -> Vec<u8>) -> *const u8 {
    // create a `Vec<u8>` from the pointer and length
    // here we could also use Rust's excellent FFI
    // libraries to read a string, but for simplicity,
    // we are using the same method as for plain byte arrays
    let data = Vec::from_raw_parts(ptr, len, len);

    let result = func(data, out_len);
    let ptr = result.as_ptr();

    // take ownership of the memory block where the result string
    // is written and ensure its destructor is not
    // called whe the object goes out of scope
    // at the end of the function
    std::mem::forget(result);
    // return the pointer to the uppercase string
    // so the runtime can read data from this offset
    ptr
}

unsafe fn pattern2(ptr: *mut u8, len: usize, func : fn(input: &[u8]) -> Result<Vec<u8>, Error>) -> *const u8 {
    //let data = Vec::from_raw_parts(ptr, len, len);

    let data = ::std::slice::from_raw_parts(
        ptr,
        len,
    );

    let result_or_err = func(data);
    match result_or_err {
        Err(error) => panic!("{:?}", error),
        _ => ()
    };
    let result = result_or_err.unwrap();

    let ptr = result.as_ptr();

    // take ownership of the memory block where the result string
    // is written and ensure its destructor is not
    // called whe the object goes out of scope
    // at the end of the function
    std::mem::forget(result);
    // return the pointer to the uppercase string
    // so the runtime can read data from this offset
    ptr
}

fn decode_block(input: Vec<u8>, out_len : &mut u32) -> Vec<u8> {
    let res = bencode::decode(input);
    match res {
        Ok(v) => {
            *out_len = v.len() as u32;
            return v;
        }
        Err(x) => panic!("{:#?}", x)
    }
}

fn decode_block2(input: Vec<u8>, out_len : &mut u32) -> Vec<u8> {
        // A JSON deserializer. You can use any Serde Deserializer here.
        let mut deserializer = bt_bencode::Deserializer::from_slice(&input);

        // A compacted JSON serializer. You can use any Serde Serializer here.
        let output = Vec::new();
        let mut serializer =serde_ipld_dagcbor::Serializer::new(output);
    
        // Prints `{"a boolean":true,"an array":[3,2,1]}` to stdout.
        // This line works with any self-describing Deserializer and any Serializer.
        serde_transcode::transcode(&mut deserializer, &mut serializer).unwrap();
    
        // read a Rust `String` from the byte array,
        //let input_str = String::from_utf8(data).unwrap();
        // transform the string to uppercase, then turn it into owned bytes
        //let mut upper = input_str.as_bytes().to_owned();
        let out = serializer.into_inner();
        *out_len = out.len() as u32;

        return out
}

#[no_mangle]
pub unsafe fn lbw() {
    let dig1 : &[u8] = &[0x1 ; 20];
    let mh1 = Multihash::wrap(0x11,dig1).unwrap();
    let c = libipld::Cid::new_v1(0x55, mh1);
    load_block_wrapper(c);
}

///*

extern {
    fn load_block(cid_bytes: *const u8, cid_length: u8) -> *const u8;
}

extern {
    fn foo(info : u32) -> ();
}

unsafe fn load_block_wrapper(blk_cid : Cid) -> &'static [u8] {
    let blk_cid_bytes = blk_cid.to_bytes();
    let cidptr = blk_cid_bytes.as_ptr();

    foo(42);
    let blk_with_len_ptr = load_block(cidptr, blk_cid_bytes.len() as u8);
    let block_len = *(blk_with_len_ptr as *const u64);

    let blk_ptr = (blk_with_len_ptr as usize + 8) as *const u8;
    let block_data = ::std::slice::from_raw_parts(
        blk_ptr,
        block_len as usize,
    );
    return block_data
}
//*/
/*
unsafe fn load_block_wrapper(blk_cid : Cid) -> &'static [u8] {
    let blk_cid_bytes = blk_cid.to_bytes();
    let cidptr = blk_cid_bytes.as_ptr();

    let mut block_len = 0;
    let res = load_block_err(cidptr, blk_cid_bytes.len() as u8, &mut block_len);
    match res {
        Err(_) => panic!("error"),
        Ok(blk_ptr) => {
            let block_data = ::std::slice::from_raw_parts(
                blk_ptr,
                block_len as usize,
            );
            block_data
        }
    }
}

*/
unsafe fn load_block_err(cid_bytes: *const u8, cid_length: u8, block_len : &mut u32) -> Result<*const u8, Error> {
    let mut block_store = BTreeMap::new();

    let dig1 : &[u8] = &[0x1 ; 20];
    let mh1 = Multihash::wrap(0x11,dig1)?;
    block_store.insert(libipld::Cid::new_v1(0x55, mh1), dig1);

    let dig2 : &[u8] = &[0x2 ; 20];
    let mh2 = Multihash::wrap(0x11,dig2)?;
    block_store.insert(libipld::Cid::new_v1(0x55, mh2), dig2);

    let cid_vec = Vec::from_raw_parts(cid_bytes as *mut u8, cid_length as usize, cid_length as usize);
    let cid_bytes: &[u8] = &cid_vec;
    let cid_result = libipld::Cid::read_bytes(cid_bytes);
    match cid_result {
        Ok(c) => {
            let block_entry = block_store.get(&c).ok_or(Error::msg("not found"))?;
            let block_data = block_entry.to_owned();
            *block_len = block_data.len() as u32;
            std::mem::forget(block_store);
            return Ok(block_data.as_ptr())
        }
        Err(_) => panic!("could not read the CID"),
    }
}

#[no_mangle]
pub unsafe fn load_adl(ptr: *mut u8, len: usize) -> *const u8  { 
    pattern2(ptr, len, load_adl_internal)
}

#[no_mangle]
pub unsafe fn seek_adl(adlptr: *mut u8, offset : i64, whence : u32) -> u64  {
    let mut f : FileReader = std::ptr::read(adlptr as *const _);
    let res = seek_adl_safe(&mut f, offset, whence);

    foo(res as u32 + 2000000);
    std::mem::forget(f);

    return res
}

fn seek_adl_safe(f : &mut FileReader, offset : i64, whence : u32) -> u64  {
    let mut new_offset : i64 = *f.offset as i64;
    match whence {
        0 => new_offset = offset,
        1 => new_offset += offset,
        2 => new_offset = (f.length as i64) + offset,
        _ => panic!("unsupported whence")
    }

    if new_offset < 0 {
        panic!("offset cannot be less than 0")
    }

    *f.offset = new_offset as u64;
    return *f.offset;
}

#[no_mangle]
pub unsafe fn read_adl(adlptr: *mut u8, bufptr : *mut u8, bufleni : i32) -> u32  {
    foo(1);
    let mut f : FileReader = std::ptr::read(adlptr as *const _) ;
    let mut buf = Vec::from_raw_parts(bufptr, bufleni.try_into().unwrap(), bufleni.try_into().unwrap());
    let res = read_adl_safer(&mut f, &mut buf);

    std::mem::forget(f);
    std::mem::forget(buf);

    res
}

fn read_adl_safer(f : &mut FileReader, buf : &mut [u8]) -> u32 {
    unsafe {foo(2);}
    unsafe {foo(*f.offset as u32 + 100000);}
    let buflen =buf.len() as u32;

    // skip if past the end
    if *f.offset >= f.length {
        panic!("tried reading past the end of the file")
    }

    let mut at = 0;
    let mut piece_num = 0;
    let mut bufrem = buflen;

    while at < f.length && bufrem > 0 {
        if *f.offset > at+f.piece_len {
			at += f.piece_len;
            piece_num += 1;
			continue
		}

        // fastforward the first one if needed.
        let blk_cid = f.pieces[piece_num];
        let block_data : &[u8];


        unsafe {foo(8);}
        unsafe {block_data = load_block_wrapper(blk_cid);}
        unsafe {foo(9);}

		if at < *f.offset {
            let delta = (*f.offset - at) as usize;

            let mut num_to_copy = bufrem;
            let block_rem = (block_data.len() - (delta as usize)) as u32;
            if num_to_copy > block_rem {
                num_to_copy = block_rem;
            }
            let numcpy: usize = num_to_copy.try_into().unwrap();

            let buf_offset: usize = (buflen - bufrem).try_into().unwrap();
            buf[(buf_offset as usize)..(buf_offset + numcpy)].copy_from_slice(&block_data[(delta as usize)..(delta+numcpy)]);
            bufrem-=numcpy as u32;
            at += numcpy as u64;
		} else {
            let mut num_to_copy = bufrem;
            let block_rem = block_data.len() as u32;
            if num_to_copy > block_rem {
                num_to_copy = block_rem;
            }
            let numcpy = num_to_copy;

            let buf_offset = buflen - bufrem;
            buf[(buf_offset as usize)..((buf_offset + numcpy) as usize)].copy_from_slice(&block_data[0..numcpy as usize]);
            bufrem-=numcpy as u32;
            at += numcpy as u64;
        }

        piece_num += 1;
    }

    let num_read = buflen - bufrem;
    unsafe {foo(100+buflen);}
    unsafe {foo(200+bufrem);}
    *f.offset += num_read as u64;
    unsafe {foo(400000+*f.offset as u32);}
    return num_read;
}

fn ipld_try_map(i : wac::Wac) -> Result<BTreeMap<Vec<u8>, wac::Wac>, Error> {
    match i {
        wac::Wac::Map(val) => return Ok(val),
        _ => return Err(libipld::error::Error::msg("not a map"))
    }
}

fn ipld_try_int(i : wac::Wac) -> Result<i128, Error> {
    match i {
        wac::Wac::Integer(val) => return Ok(val),
        _ => return Err(libipld::error::Error::msg("not an integer"))
    }
}

fn ipld_try_bytestring(i : wac::Wac) -> Result<Vec<u8>, Error> {
    match i {
        wac::Wac::String(val) => return Ok(val),
        _ => return Err(libipld::error::Error::msg("not a bytestring"))
    }
}

fn load_adl_internal<'a>(input: &[u8]) -> Result<Vec<u8>, Error> {
            // Assume node is WAC
            let node = wac::from_bytes(input)?;

            let node_map = ipld_try_map(node)?;

            let pieces_node = node_map.get("pieces".as_bytes())
                .ok_or(libipld::error::Error::msg("pieces not in node"))?;
            let pieces_bytes = ipld_try_bytestring(pieces_node.to_owned())?;
            
            const SHA1_HASH_LEN : usize = 20;
            if pieces_bytes.len() % SHA1_HASH_LEN != 0 {
                return Err(libipld::error::Error::msg("pieces string is not a multiple of 20 bytes"));
            }

            let piece_length_node = node_map.get("piece length".as_bytes())
            .ok_or(libipld::error::Error::msg("piece length not in node"))?;
            let piece_length_int = ipld_try_int(piece_length_node.to_owned())?;

            let length_node = node_map.get("length".as_bytes())
            .ok_or(libipld::error::Error::msg("length not in node"))?;
            let length_int = ipld_try_int(length_node.to_owned())?;

            let mut pieces: Vec<libipld::Cid> = Vec::new();
            for c in pieces_bytes.chunks_exact(SHA1_HASH_LEN) {
                let mh = Multihash::wrap(0x11, c)?;
                let cid = CidGeneric::new_v1(0x55, mh);
                pieces.push(cid);
            }

            let f = FileReader { 
                offset: &mut 0, 
                length: length_int as u64, 
                piece_len: piece_length_int as u64, 
                //cached_blocks: BTreeMap::new(), 
                pieces: pieces,
            };

            let f = std::mem::ManuallyDrop::new(f);

            let bytes: &[u8] = unsafe { any_as_u8_slice(&f) };
            return Ok(bytes.to_vec());
}

#[repr(C)]
struct FileReader<'a> {
    offset: &'a mut u64,
    length: u64,
    piece_len: u64,
    //cached_blocks: BTreeMap<libipld::Cid, &'a [u8]>,
    pieces: Vec<libipld::Cid>,
}

unsafe fn any_as_u8_slice<T: Sized>(p: &T) -> &[u8] {
    ::std::slice::from_raw_parts(
        (p as *const T) as *const u8,
        ::std::mem::size_of::<T>(),
    )
}
