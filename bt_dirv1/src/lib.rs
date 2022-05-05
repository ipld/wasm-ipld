use std::{collections::{BTreeMap, btree_map::Iter}, convert::TryInto, str::from_utf8, any::{Any, TypeId}};

use example::{ValueOrError, get_error, ADLorWAC};
use libipld::{cid::CidGeneric, error::Error, Cid, Multihash};

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
pub unsafe fn load_adl(ptr: *mut u8, len: u32) -> *mut ValueOrError{
    let len = len as usize;
    let block_data = ::std::slice::from_raw_parts(ptr, len);

    let result_or_err = load_adl_internal(block_data);
    match result_or_err {
        Err(error) => {
            get_error(error) as *mut ValueOrError
        },
        Ok(val) => {            
            let res = Box::new(ValueOrError {
                err : std::ptr::null(),
                value : val as *mut u8,
            });
            Box::into_raw(res)
        },
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
    let mut bx = Box::from_raw(adlptr as *mut dyn Any);    
    let res = bx.downcast::<Directory>();
    match res {
        Ok(d) => d.length,
        Err(_) => -1,
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
    let mut bx = Box::from_raw(adlptr as *mut dyn Any);
    
    let key_len = key_len as usize;
    let key = ::std::slice::from_raw_parts(key_ptr, key_len);
    let key_str = std::str::from_utf8(key);

    let res = get_key_safe(bx, key_str);
    match res {
        Ok(b) => {
            Box::into_raw(res)
        },
        Err(error) => get_error(error) as *mut ValueOrError,
    }
}

fn get_key_safe(bx : Box<dyn Any>, key : &str) -> Result<Box<ADLorWAC>, libipld::error::Error> {
    let dir_adl = bx.downcast::<Directory>().ok();
    match dir_adl {
        Some(adl) => {
            return dir_get_key(adl.dir, key)
        },
        None => (),
    }

    let dir_adl = bx.downcast::<BTDir>().ok();
    match dir_adl {
        Some(dir) => return dir_get_key(dir, key),
        None => (),
    }

    Err(libipld::error::Error::msg("type not valid"))
}

fn dir_get_key(dir : BTDir, key : &str) -> Result<Box<ADLorWAC>, libipld::error::Error> {
    let val = dir.children.get(key).ok_or("not found")?;
            let r = match val {
                BTDirElem::Dir(d) => {
                    let dbox = Box::new(d);
                    let adl_ptr = std::ptr::null();
                    let res = Box::new(ADLorWAC {
                        err : std::ptr::null(),
                        adl_ptr: Box::into_raw(dbox) as *const u8,
                        wac: std::ptr::null(),
                    });
                    res
                },
                BTDirElem::File(f) => todo!(),
            };
            return Ok(r)
}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn new_map_iter(adlptr: *mut u8) -> *const u8 {
    let mut fb = Box::from_raw(adlptr as *mut Directory);

    let mut iter = DirectoryIter{
        directory : fb,
        iter : fb.files.iter()
    }

    let iterBox = Box::new(iter);

    Box::leak(fb);
    Box::into_raw(iterBox);
}

// TODO: Need to figure out what to do for ADL functions that return Nodes
// Some possible options:
//     Return WAC - Easy, low boundary crossing, works in many situations, can't use internal signaling in an ADL to make the returned node an ADL
//     Return Pointer - Requires that the node have a way to signal what kind it presents as, more boundary crossing, potentially larger library sizes as more data types and logic are included in the ADL, built in signaling doable, less WAC round-trips
//     Return "instructions" - e.g. WAC + signaling information, CID + telling the program to load it (maybe that's always implied?). Low boundary crossing, another very fuzzy/ambiguous interface to design, may contain external signaling
//     Support some/all of the above
//
//     Idea for now: Return (Ptr or WAC)

#[repr(C)]
struct ReturnWithLength {
    ptr : *const u8,
    len : u32,
}

#[repr(C)]
struct ReturnError {
    msg : ReturnWithLength
}

#[repr(C)]
struct NodeReturn {
    adl_ptr : *const u8,
    kind : u8,
    wac : ReturnWithLength,
    error : ReturnError,
}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn iter_next(adlptr: *mut u8) -> *const u8 {
    let mut fb = Box::from_raw(adlptr as *mut DirectoryIter);
    
    // TODO: Deal with end of iter
    let n = fb.iter.next()?;

    let new_file_map<Vec<u8>, wac::Wac> = BTreeMap::new();
    new_file_map.insert("", value)
    wac::Wac::Map(new_file_map)

    //TODO: length
    let out = wac::into_bytes(input)?.into_boxed_slice();

    Box::leak(fb);
    Box::into_raw(out);
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

/// # Safety
///
/// This function assumes the adl pointer is to a valid adl node.
/// Also assumes the buffer pointer is to an allocated and usable buffer.
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
    if node_map.contains_key("length") {
        return libipld::error::Error::msg("length not in node")
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

    let files_list = node_map.get("files")?;
    let files_list = ipld_try_list(files_list.to_owned())?;

    let dir = BTDir{
        children : BTreeMap::new()
    };

    let mut start_piece = 0;
    let mut start_index = 0;
    // Do validation
    for f_dict in files_list {
        let d = ipld_try_map(f_dict)?;
        let path_segs = d.get("path")?;
        let path_segs = ipld_try_list(path_segs)?;
        let internal_dir: &mut BTDir = &mut dir;
        for (i, elem) in path_segs.iter().enumerate() {
            let s = match elem {
                wac::Wac::String(s) => from_utf8(s)?,
                _ => return Err(Error::msg("path segment not a string"))
            };

            if i != path_segs.len() -1 {
                let next_dir = match internal_dir.children.get(s) {
                    Some(elem) => elem,
                    None => {
                        let new_dir = BTDir{
                            children : BTreeMap::new()
                        };
                        dir.children.insert(s, new_dir);
                        new_dir
                    }
                };
                internal_dir = next_dir
            } else {
                let file_len = d.get("length").and_then(|w| ipld_try_int(w).ok())?;
                let num_pieces = file_len/piece_length_int;
                let f = BTFile{
                    start_offset: start_index,
                    pieces : pieces[0..3],
                    length: file_len,
                };
            }
        }
        ipld_try_int(v_name)?;

        dir.children.insert(k, v_name)?;
    }

    let d = Directory { 
        piece_len: piece_length_int as u64,
        pieces, 
        files: files_map,
        offset: todo!(),
        length: todo!(),
        dir,
    };

    let db = Box::new(d);
    Ok(db)
}

enum BTDirElem {
    Dir(BTDir),
    File(BTFile)
}

struct BTDir {
    children : BTreeMap<String, BTDirElem>
}

struct BTFile {
    start_offset: u64,
    pieces: Vec<libipld::Cid>,
    length: u64,
}

struct Directory {
    offset: u64,
    length: u64,
    piece_len: u64,
    pieces: Vec<libipld::Cid>,
    dir : BTDir
}

struct DirectoryIter {
    directory : &Directory,
    iter : Iter<Vec<u8>, wac::Wac>
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
