use std::{
    any::Any,
    borrow::BorrowMut,
    collections::{btree_map::Iter, BTreeMap},
    convert::TryInto,
    str::from_utf8,
};

use example::{
    byte_vec_to_byte_wrapper, get_error, load_raw_block_caller, ADLorWAC, ByteWrapper, IterResp,
    ValueOrError,
};
use libipld::{cid::CidGeneric, error::Error, Multihash};
use ouroboros::self_referencing;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// Takes a pointer and length of a byte array containing WAC encoded data and returns
/// a pointer to the ADL instance.
///
/// # Safety
///
/// This function assumes the block pointer has size have been allocated and filled.
#[no_mangle]
pub unsafe fn load_adl(ptr: *mut u8, len: u32) -> *mut ValueOrError {
    let len = len as usize;
    let block_data = ::std::slice::from_raw_parts(ptr, len);

    let result_or_err = load_adl_internal(block_data);
    match result_or_err {
        Err(error) => get_error(error) as *mut ValueOrError,
        Ok(val) => {
            let res = Box::new(ValueOrError {
                err: std::ptr::null(),
                value: Box::into_raw(val) as *mut u8,
            });
            Box::into_raw(res)
        }
    }
}

/// Takes a pointer to an ADL and returns its length.
///
/// TODO: Should we allow returning an error?
///
/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn adl_len(adlptr: *mut u8) -> i64 {
    let bx = Box::from_raw(adlptr as *mut dyn Any);
    let res = bx.downcast::<BTDir>();
    match res {
        Ok(d) => {
            let ret = d.children.len().try_into().unwrap();
            Box::leak(d);
            ret
        }
        Err(d) => {
            Box::leak(d);
            -1
        }
    }
}

/// Takes a pointer to an ADL as well as a buffer and its length
/// and returns either an error, an ADL pointer, or WAC data.
///
/// TODO: Allow returning an error
///
/// # Safety
///
/// This function assumes the adl pointer is to a valid adl node.
/// Also assumes the buffer pointer is to an allocated and usable buffer.
#[no_mangle]
pub unsafe fn get_key(adlptr: *mut u8, key_ptr: *mut u8, key_len: i32) -> *const ADLorWAC {
    let bx = Box::from_raw(adlptr as *mut dyn Any);

    let key_len = key_len as usize;
    let key = ::std::slice::from_raw_parts(key_ptr, key_len);

    let res = get_key_safe(bx, key);
    match res {
        Ok(b) => Box::into_raw(b),
        Err(err) => {
            let err_str = err.to_string().as_bytes().to_owned();
            let bx = err_str.into_boxed_slice();
            let bx_len = bx.len() as u32;
            let bytes_ptr = Box::into_raw(bx) as *const u8;

            let res = Box::new(ADLorWAC {
                err: Box::into_raw(Box::new(ByteWrapper {
                    msg_len: bx_len,
                    msg_ptr: bytes_ptr,
                })),
                adl_ptr: std::ptr::null(),
                wac: std::ptr::null(),
            });
            Box::into_raw(res)
        }
    }
}

fn get_key_safe(
    bx: Box<dyn Any>,
    key_bytes: &[u8],
) -> Result<Box<ADLorWAC>, libipld::error::Error> {
    let key = std::str::from_utf8(key_bytes)?;

    let dir_adl = bx.downcast::<BTDir>().ok();
    match dir_adl {
        Some(dir) => return dir_get_key(*dir, key),
        None => (),
    }

    Err(libipld::error::Error::msg("type not valid"))
}

fn dir_get_key(dir: BTDir, key: &str) -> Result<Box<ADLorWAC>, libipld::error::Error> {
    let val = dir
        .children
        .get(key)
        .ok_or(libipld::error::Error::msg("not found"))?;
    let r = match val {
        BTDirElem::Dir(d) => {
            let dbox: Box<dyn Any> = Box::new(d);
            let res = Box::new(ADLorWAC {
                err: std::ptr::null(),
                adl_ptr: Box::into_raw(dbox) as *const u8,
                wac: std::ptr::null(),
            });
            res
        }
        BTDirElem::File(f) => todo!(),
    };
    return Ok(r);
}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn new_map_iter(adlptr: *mut u8) -> *const u8 {
    let bx = Box::from_raw(adlptr as *mut dyn Any);
    let dir_adl = bx.downcast::<BTDir>().expect("not a map");

    let iter = DirectoryIter {
        iter: dir_adl.children.iter(),
    };

    Box::leak(dir_adl);
    let iterBox: Box<dyn Any> = Box::new(iter);

    Box::into_raw(iterBox) as *const u8
}

// TODO: Need to figure out what to do for ADL functions that return Nodes
// Some possible options:
//     Return WAC - Easy, low boundary crossing, works in many situations, can't use internal signaling in an ADL to make the returned node an ADL
//     Return Pointer - Requires that the node have a way to signal what kind it presents as, more boundary crossing, potentially larger library sizes as more data types and logic are included in the ADL, built in signaling doable, less WAC round-trips
//     Return "instructions" - e.g. WAC + signaling information, CID + telling the program to load it (maybe that's always implied?). Low boundary crossing, another very fuzzy/ambiguous interface to design, may contain external signaling
//     Support some/all of the above
//
//     Idea for now: Return (Ptr or WAC)

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn iter_next(adlptr: *mut u8) -> *const IterResp {
    let bx = Box::from_raw(adlptr as *mut dyn Any);
    let mut dir_iter_adl = bx.downcast::<DirectoryIter>().expect("not a map iterator");

    let dir_iter = &mut *dir_iter_adl;
    let next_item = dir_iter.iter.next();
    let ret = match next_item {
        Some(kv_pair) => {
            let val_bx = Box::new(kv_pair.1);
            let res = Box::new(IterResp {
                key: byte_vec_to_byte_wrapper(kv_pair.0.to_string().into_bytes()),
                value_adl_ptr: Box::into_raw(val_bx) as *const u8,
                val_wac: std::ptr::null(),
                err: byte_vec_to_byte_wrapper("end of iterator".as_bytes().to_owned()),
            });
            res
        }
        None => {
            let res = Box::new(IterResp {
                key: std::ptr::null(),
                value_adl_ptr: std::ptr::null(),
                val_wac: std::ptr::null(),
                err: byte_vec_to_byte_wrapper("end of iterator".as_bytes().to_owned()),
            });
            res
        }
    };

    Box::leak(dir_iter_adl);
    Box::into_raw(ret)
}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn new_bytes_reader(adlptr: *mut u8) -> *const u8 {
    let bx = Box::from_raw(adlptr as *mut dyn Any);
    let file_adl = bx.downcast::<BTFile>().expect("not a file");

    let reader = FileReader {
        file: file_adl.as_ref(),
        offset: 0,
        length: file_adl.length,
    };

    let reader_box: Box<dyn Any> = Box::new(reader);

    Box::leak(file_adl);
    Box::into_raw(reader_box) as *const u8
}

struct FileReader {
    file: *const BTFile,
    offset: u64,
    length: u64,
}

// Bytes

/// Takes a pointer to an ADL along with the offset and whence enum.
/// It returns the offset from the start of the data.
///
/// TODO: Allow returning an error
///
/// Whence enum:
/// 0 - seek relative to the origin of the file
/// 1 - seek relative to the current offset
/// 2 - seek relative to the end
///
/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn seek_adl(adlptr: *mut u8, offset: i64, whence: u32) -> u64 {
    // Get ADL
    let bx = Box::from_raw(adlptr as *mut dyn Any);
    let mut file_adl = bx.downcast::<FileReader>().expect("not a file");
    let res = seek_adl_safe(file_adl.as_mut(), offset, whence);

    // Release ADL memory
    Box::leak(file_adl);
    res
}

/// Takes a pointer to an ADL as well as a buffer and its length
/// and returns the number of bytes read.
///
/// TODO: Allow returning an error
///
/// # Safety
///
/// This function assumes the adl pointer is to a valid adl node.
/// Also assumes the buffer pointer is to an allocated and usable buffer.
#[no_mangle]
pub unsafe fn read_adl(adlptr: *mut u8, bufptr: *mut u8, bufleni: i32) -> u32 {
    // Get ADL
    let bx = Box::from_raw(adlptr as *mut dyn Any);
    let mut file_adl = bx.downcast::<&mut FileReader>().expect("not a file");

    // Get buffer
    let mut buf = Vec::from_raw_parts(
        bufptr,
        bufleni.try_into().unwrap(),
        bufleni.try_into().unwrap(),
    );

    let fi_ptr = file_adl.file;
    let fi = &*fi_ptr;
    // Read into the buffer
    let res = read_adl_safer(&mut file_adl, fi, &mut buf);

    // Release ADL
    Box::leak(file_adl);

    // Release the buffer
    let b_buf = Box::new(buf);
    Box::leak(b_buf);
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
    f.offset
}

fn read_adl_safer(f: &mut FileReader, file_info: &BTFile, buf: &mut [u8]) -> u32 {
    let buflen = buf.len() as u32;

    // skip if past the end
    if f.offset >= f.length {
        panic!("tried reading past the end of the file")
    }

    let mut at = 0;
    let mut piece_num = 0;
    let mut bufrem = buflen;

    // handle the first block
    piece_num = ((f.offset + file_info.start_offset) / file_info.piece_length) as usize;
    let start_delta = ((f.offset + file_info.start_offset) % file_info.piece_length) as usize;
    at = f.offset;

    while at < f.length && bufrem > 0 {
        // fastforward the first one if needed.
        let blk_cid = file_info.pieces[piece_num];
        let block_data: Box<[u8]>;

        unsafe {
            block_data = load_raw_block_caller(blk_cid);
        }

        if at == f.offset {
            let mut num_to_copy = bufrem;
            let block_rem = (block_data.len() - start_delta) as u32;
            if num_to_copy > block_rem {
                num_to_copy = block_rem;
            }
            let numcpy: usize = num_to_copy.try_into().unwrap();

            let buf_offset: usize = (buflen - bufrem).try_into().unwrap();
            buf[(buf_offset as usize)..(buf_offset + numcpy)]
                .copy_from_slice(&block_data[start_delta..(start_delta + numcpy)]);
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
    num_read
}

fn ipld_try_map(i: wac::Wac) -> Result<BTreeMap<Vec<u8>, wac::Wac>, Error> {
    match i {
        wac::Wac::Map(val) => Ok(val),
        _ => Err(libipld::error::Error::msg("not a map")),
    }
}

fn ipld_try_list(i: wac::Wac) -> Result<Vec<wac::Wac>, Error> {
    match i {
        wac::Wac::List(val) => Ok(val),
        _ => Err(libipld::error::Error::msg("not a map")),
    }
}

fn ipld_try_int(i: wac::Wac) -> Result<i128, Error> {
    match i {
        wac::Wac::Integer(val) => Ok(val),
        _ => Err(libipld::error::Error::msg("not an integer")),
    }
}

fn ipld_try_bytestring(i: wac::Wac) -> Result<Vec<u8>, Error> {
    match i {
        wac::Wac::String(val) => Ok(val),
        _ => Err(libipld::error::Error::msg("not a bytestring")),
    }
}

fn load_adl_internal(input: &[u8]) -> Result<Box<dyn Any>, Error> {
    // Assume node is WAC
    let node = wac::from_bytes(input)?;

    let node_map = ipld_try_map(node)?;

    // assert length missing
    if node_map.contains_key("length".as_bytes()) {
        return Err(libipld::error::Error::msg("length not in node"));
    }

    let pieces_node = node_map
        .get("pieces".as_bytes())
        .ok_or_else(|| libipld::error::Error::msg("pieces not in node"))?;
    let pieces_bytes = ipld_try_bytestring(pieces_node.to_owned())?;

    const SHA1_HASH_LEN: usize = 20;
    if pieces_bytes.len() % SHA1_HASH_LEN != 0 {
        return Err(libipld::error::Error::msg(
            "pieces string is not a multiple of 20 bytes",
        ));
    }

    let piece_length_node = node_map
        .get("piece length".as_bytes())
        .ok_or_else(|| libipld::error::Error::msg("piece length not in node"))?;
    let piece_length_int = ipld_try_int(piece_length_node.to_owned())?;

    let mut pieces: Vec<libipld::Cid> = Vec::new();
    for c in pieces_bytes.chunks_exact(SHA1_HASH_LEN) {
        let mh = Multihash::wrap(0x11, c)?;
        let cid = CidGeneric::new_v1(0x55, mh);
        pieces.push(cid);
    }

    let files_list = node_map
        .get("files".as_bytes())
        .ok_or_else(|| libipld::error::Error::msg("files not in node"))?;
    let files_list = ipld_try_list(files_list.to_owned())?;

    let dir = &mut BTDir {
        children: BTreeMap::new(),
    };

    let mut start_piece = 0;
    let mut start_index = 0;
    // Do validation
    for f_dict in files_list {
        let d = ipld_try_map(f_dict)?;
        let path_segs = d
            .get("path".as_bytes())
            .ok_or_else(|| libipld::error::Error::msg("path not in node"))?;
        let path_segs = ipld_try_list(path_segs.to_owned())?;
        let mut internal_dir: &mut BTDir = dir;
        for (i, elem) in path_segs.iter().enumerate() {
            let s = match elem {
                wac::Wac::String(s) => from_utf8(s)?,
                _ => return Err(Error::msg("path segment not a string")),
            };

            if i != path_segs.len() - 1 {
                let next_dir = internal_dir
                    .children
                    .entry(s.to_owned())
                    .or_insert_with(|| {
                        BTDirElem::Dir(BTDir {
                            children: BTreeMap::new(),
                        })
                    });
                match next_dir {
                    BTDirElem::Dir(nd) => {
                        internal_dir = nd;
                    }
                    BTDirElem::File(_) => {
                        return Err(libipld::error::Error::msg(
                            "cannot have file and directory with the same name",
                        ))
                    }
                }
            } else {
                let file_len = d
                    .get("length".as_bytes())
                    .and_then(|w| ipld_try_int(w.to_owned()).ok())
                    .ok_or_else(|| libipld::error::Error::msg("file length not found"))?;

                let first_blk_len = piece_length_int - start_index;
                let mut num_pieces = 1;
                let mut new_starting_index = 0;
                if file_len >= first_blk_len {
                    num_pieces += ((file_len - first_blk_len) / piece_length_int) as usize;
                    let rem = (file_len - first_blk_len) % piece_length_int;
                    if rem > 0 {
                        num_pieces += 1;
                        new_starting_index = rem;
                    }
                } else {
                    new_starting_index = start_index + file_len;
                }

                let f = BTFile {
                    start_offset: start_index as u64,
                    pieces: pieces[start_piece..start_piece + num_pieces].to_vec(),
                    length: file_len as u64,
                    piece_length: piece_length_int as u64,
                };
                start_index = new_starting_index;
                if internal_dir
                    .children
                    .insert(s.to_string(), BTDirElem::File(f))
                    .is_some()
                {
                    return Err(libipld::error::Error::msg(
                        "cannot have a file name repeated",
                    ));
                }
            }
        }
    }

    let d = BTDir { children: todo!() };

    let db: Box<dyn Any> = Box::new(d);
    Ok(db)
}

enum BTDirElem {
    Dir(BTDir),
    File(BTFile),
}

struct BTDir {
    children: BTreeMap<String, BTDirElem>,
}

struct BTFile {
    start_offset: u64,
    pieces: Vec<libipld::Cid>,
    length: u64,
    piece_length: u64,
}

struct DirectoryIter<'a> {
    iter: Iter<'a, String, BTDirElem>,
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
