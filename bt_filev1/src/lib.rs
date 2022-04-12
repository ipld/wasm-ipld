use std::{collections::BTreeMap, convert::TryInto};

use libipld::{cid::CidGeneric, error::Error, Cid, Multihash};

use wac;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
//#[cfg(feature = "wee_alloc")]
//#[global_allocator]
//static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Allocate memory into the module's linear memory
/// and return the offset to the start of the block.
#[no_mangle]
pub fn myalloc(len: usize) -> *mut u8 {
    let buf = vec![0u8; len];
    Box::leak(buf.into_boxed_slice()).as_mut_ptr()
}

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn load_block(cid_bytes: *const u8, cid_length: u8) -> *const u8;
}

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn log_marker(info: u32) -> ();
}

#[cfg(target_arch = "wasm32")]
unsafe fn load_block_wrapper(blk_cid: Cid) -> Box<[u8]> {
    let blk_cid_bytes = blk_cid.to_bytes();
    let cidptr = blk_cid_bytes.as_ptr();

    log_marker(42);
    let blk_with_len_ptr = load_block(cidptr, blk_cid_bytes.len() as u8);
    let block_len = *(blk_with_len_ptr as *const u64);

    let blk_ptr = (blk_with_len_ptr as usize + 8) as *const u8;
    let block_data = ::std::slice::from_raw_parts(blk_ptr, block_len as usize);
    return block_data.to_owned().into_boxed_slice();
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn log_marker(_marker: u32) -> () {
    //println!("Foo: {:#?}", info);
}

#[cfg(not(target_arch = "wasm32"))]
unsafe fn load_block_wrapper(blk_cid: Cid) -> Box<[u8]> {
    let mut block_len = 0;
    log_marker(42);
    let res = load_block_err(blk_cid, &mut block_len);
    match res {
        Err(_) => panic!("error"),
        Ok(blk_data) => {
            let x = blk_data.into_boxed_slice();
            x
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn load_block_err(c: Cid, block_len: &mut u32) -> Result<Vec<u8>, Error> {
    let mut block_store = BTreeMap::new();

    let dig1 = hex::decode("38666b8ba500faa5c2406f4575d42a92379844c2")?;
    let blk1: &[u8] = &[0x61; 30];
    let mh1 = Multihash::wrap(0x11, &dig1)?;
    block_store.insert(libipld::Cid::new_v1(0x55, mh1), blk1);

    let dig2 = hex::decode("45dfb79d668374f6578b3128746dce59b7a02e80")?;
    let blk2: &[u8] = &[0x62; 10];
    let mh2 = Multihash::wrap(0x11, &dig2)?;
    block_store.insert(libipld::Cid::new_v1(0x55, mh2), blk2);

    let block_entry = block_store.get(&c).ok_or(Error::msg("not found"))?;
    let mut block_data = Vec::new();
    block_data.extend_from_slice(block_entry);
    *block_len = block_data.len() as u32;
    let res = Ok(block_data);
    return res;
}

#[no_mangle]
pub unsafe fn load_adl(ptr: *mut u8, len: usize) -> *const u8 {
    let block_data = ::std::slice::from_raw_parts(ptr, len);

    let result_or_err = load_adl_internal(block_data);
    match result_or_err {
        Err(error) => panic!("{:?}", error),
        Ok(val) => Box::into_raw(val) as *const u8,
    }
}

#[no_mangle]
pub unsafe fn seek_adl(adlptr: *mut u8, offset: i64, whence: u32) -> u64 {
    let mut fb = Box::from_raw(adlptr as *mut FileReader);
    let res = seek_adl_safe(fb.as_mut(), offset, whence);

    Box::leak(fb);
    res
}

fn seek_adl_safe(f: &mut FileReader, offset: i64, whence: u32) -> u64 {
    let mut new_offset: i64 = f.offset as i64;
    match whence {
        0 => new_offset = offset,
        1 => new_offset += offset,
        2 => new_offset = (f.length as i64) + offset,
        _ => panic!("unsupported whence"),
    }

    if new_offset < 0 {
        panic!("offset cannot be less than 0")
    }

    f.offset = new_offset as u64;
    return f.offset;
}

#[no_mangle]
pub unsafe fn read_adl(adlptr: *mut u8, bufptr: *mut u8, bufleni: i32) -> u32 {
    let mut fb = Box::from_raw(adlptr as *mut FileReader);

    let mut buf = Vec::from_raw_parts(
        bufptr,
        bufleni.try_into().unwrap(),
        bufleni.try_into().unwrap(),
    );
    let res = read_adl_safer(fb.as_mut(), &mut buf);

    Box::leak(fb);
    let b_buf = Box::new(buf);
    Box::leak(b_buf);
    res
}

fn read_adl_safer(f: &mut FileReader, buf: &mut [u8]) -> u32 {
    let buflen = buf.len() as u32;

    // skip if past the end
    if f.offset >= f.length {
        panic!("tried reading past the end of the file")
    }

    let mut at = 0;
    let mut piece_num = 0;
    let mut bufrem = buflen;

    while at < f.length && bufrem > 0 {
        if f.offset > at + f.piece_len {
            at += f.piece_len;
            piece_num += 1;
            continue;
        }

        // fastforward the first one if needed.
        let blk_cid = f.pieces[piece_num];
        let block_data: Box<[u8]>;

        unsafe {
            block_data = load_block_wrapper(blk_cid);
        }

        if at < f.offset {
            let delta = (f.offset - at) as usize;

            let mut num_to_copy = bufrem;
            let block_rem = (block_data.len() - (delta as usize)) as u32;
            if num_to_copy > block_rem {
                num_to_copy = block_rem;
            }
            let numcpy: usize = num_to_copy.try_into().unwrap();

            let buf_offset: usize = (buflen - bufrem).try_into().unwrap();
            buf[(buf_offset as usize)..(buf_offset + numcpy)]
                .copy_from_slice(&block_data[(delta as usize)..(delta + numcpy)]);
            bufrem -= numcpy as u32;
            at = numcpy as u64 + f.offset;
        } else {
            let mut num_to_copy = bufrem;
            let block_rem = block_data.len() as u32;
            if num_to_copy > block_rem {
                num_to_copy = block_rem;
            }
            let numcpy = num_to_copy;

            let buf_offset = buflen - bufrem;
            buf[(buf_offset as usize)..((buf_offset + numcpy) as usize)]
                .copy_from_slice(&block_data[0..numcpy as usize]);
            bufrem -= numcpy as u32;
            at += numcpy as u64;
        }

        piece_num += 1;
    }

    let num_read = buflen - bufrem;
    f.offset += num_read as u64;
    return num_read;
}

fn ipld_try_map(i: wac::Wac) -> Result<BTreeMap<Vec<u8>, wac::Wac>, Error> {
    match i {
        wac::Wac::Map(val) => return Ok(val),
        _ => return Err(libipld::error::Error::msg("not a map")),
    }
}

fn ipld_try_int(i: wac::Wac) -> Result<i128, Error> {
    match i {
        wac::Wac::Integer(val) => return Ok(val),
        _ => return Err(libipld::error::Error::msg("not an integer")),
    }
}

fn ipld_try_bytestring(i: wac::Wac) -> Result<Vec<u8>, Error> {
    match i {
        wac::Wac::String(val) => return Ok(val),
        _ => return Err(libipld::error::Error::msg("not a bytestring")),
    }
}

fn load_adl_internal<'a>(input: &[u8]) -> Result<Box<FileReader>, Error> {
    // Assume node is WAC
    let node = wac::from_bytes(input)?;

    let node_map = ipld_try_map(node)?;

    let pieces_node = node_map
        .get("pieces".as_bytes())
        .ok_or(libipld::error::Error::msg("pieces not in node"))?;
    let pieces_bytes = ipld_try_bytestring(pieces_node.to_owned())?;

    const SHA1_HASH_LEN: usize = 20;
    if pieces_bytes.len() % SHA1_HASH_LEN != 0 {
        return Err(libipld::error::Error::msg(
            "pieces string is not a multiple of 20 bytes",
        ));
    }

    let piece_length_node = node_map
        .get("piece length".as_bytes())
        .ok_or(libipld::error::Error::msg("piece length not in node"))?;
    let piece_length_int = ipld_try_int(piece_length_node.to_owned())?;

    let length_node = node_map
        .get("length".as_bytes())
        .ok_or(libipld::error::Error::msg("length not in node"))?;
    let length_int = ipld_try_int(length_node.to_owned())?;

    let mut pieces: Vec<libipld::Cid> = Vec::new();
    for c in pieces_bytes.chunks_exact(SHA1_HASH_LEN) {
        let mh = Multihash::wrap(0x11, c)?;
        let cid = CidGeneric::new_v1(0x55, mh);
        pieces.push(cid);
    }

    let f = FileReader {
        offset: 0,
        length: length_int as u64,
        piece_len: piece_length_int as u64,
        pieces: pieces,
    };

    let fb = Box::new(f);
    return Ok(fb);
}

#[repr(C)]
struct FileReader {
    offset: u64,
    length: u64,
    piece_len: u64,
    pieces: Vec<libipld::Cid>,
}

#[cfg(test)]
mod tests {
    use crate::{load_adl, read_adl, seek_adl};

    #[test]
    fn test_full_read() {
        let hex_wac_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr = load_adl(wac_file_root.as_mut_ptr(), wac_file_root.len());
            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(40, 0);

            let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!(num_read, 40);
            assert_eq!(buffer.as_slice()[0..30], [0x61; 30]);
            assert_eq!(buffer.as_slice()[30..], [0x62; 10]);
        }
    }

    #[test]
    fn test_partial_reads() {
        let hex_wac_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr = load_adl(wac_file_root.as_mut_ptr(), wac_file_root.len());
            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(20, 0);

            let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!(num_read, 20);
            assert_eq!(buffer.as_slice()[0..20], [0x61; 20]);

            let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!(num_read, 20);
            assert_eq!(buffer.as_slice()[0..10], [0x61; 10]);
            assert_eq!(buffer.as_slice()[10..], [0x62; 10]);
        }
    }

    #[test]
    fn test_seek_read() {
        let hex_wac_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr = load_adl(wac_file_root.as_mut_ptr(), wac_file_root.len());
            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(20, 0);

            let seek_to = seek_adl(adl_ptr as *mut u8, 15, 0);
            assert_eq!(seek_to, 15);

            let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!(num_read, 20);
            assert_eq!(buffer.as_slice()[0..15], [0x61; 15]);
            assert_eq!(buffer.as_slice()[15..], [0x62; 5]);
        }
    }
}
