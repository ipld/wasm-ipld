use std::{
    borrow::BorrowMut,
    collections::BTreeMap,
    convert::TryInto,
    ffi::c_void,
    str::{from_utf8, FromStr},
};

use helpers::{
    byte_vec_to_byte_wrapper, load_raw_block_caller, load_wac_block_caller, ADLorWAC, ByteWrapper,
    IterResp, ReadResp,
};
use libipld::{cid::CidGeneric, error::Error, Cid, Multihash};

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

/// # Safety
///
/// This function should not exist, and if you're calling it you're doing something wrong
#[no_mangle]
pub unsafe fn does_nothing() {
    let c = Cid::from_str("forcing the inclusion an unused extern function").unwrap();
    let b = load_wac_block_caller(c).unwrap();
    if b.len() == 0 {
        panic!("you shouldn't call this function")
    }
}

/// Takes a pointer and length of a byte array containing WAC encoded data and returns
/// a pointer to the ADL instance.
///
/// # Safety
///
/// This function assumes the block pointer has size have been allocated and filled.
#[no_mangle]
pub unsafe fn load_adl(ptr: *mut u8, len: u32) -> *mut ADLorWAC {
    BtAdl {}.load_adl(ptr, len)
}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn new_bytes_reader(adlptr: *const c_void) -> *mut c_void {
    BtAdl {}.new_bytes_reader(adlptr)
}

/// Takes a pointer to an ADL as well as a buffer and its length
/// and returns the number of bytes read.
///
/// # Safety
///
/// This function assumes the adl pointer is to a valid adl node.
/// Also assumes the buffer pointer is to an allocated and usable buffer.
#[no_mangle]
pub unsafe fn read_adl(adlptr: *mut u8, bufptr: *mut u8, bufleni: i32) -> *const ReadResp {
    BtAdl {}.read_adl(adlptr, bufptr, bufleni)
}

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
pub unsafe fn seek_adl(adlptr: *mut c_void, offset: i64, whence: u32) -> u64 {
    BtAdl {}.seek_adl(adlptr, offset, whence)
}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn new_map_iter(adlptr: *const c_void) -> *mut c_void {
    BtAdl {}.new_map_iter(adlptr)
}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn iter_next(adlptr: *mut c_void) -> *const IterResp {
    BtAdl {}.iter_next(adlptr)
}

/// Takes a pointer to an ADL as well as a buffer and its length
/// and returns either an error, an ADL pointer, or WAC data.
///
/// # Safety
///
/// This function assumes the adl pointer is to a valid adl node.
/// Also assumes the buffer pointer is to an allocated and usable buffer.
#[no_mangle]
pub unsafe fn get_key(adlptr: *mut c_void, key_ptr: *mut u8, key_len: i32) -> *const ADLorWAC {
    BtAdl {}.get_key(adlptr, key_ptr, key_len)
}

/// Takes a pointer to an ADL and returns its length.
///
/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn adl_len(adlptr: *const c_void) -> i64 {
    BtAdl {}.adl_len(adlptr)
}

struct BtAdl {}
impl BtAdl {
    /// Takes a pointer and length of a byte array containing WAC encoded data and returns
    /// a pointer to the ADL instance.
    ///
    /// # Safety
    ///
    /// This function assumes the block pointer has size have been allocated and filled.
    unsafe fn load_adl(&self, ptr: *mut u8, len: u32) -> *mut ADLorWAC {
        let len = len as usize;
        let block_data = ::std::slice::from_raw_parts(ptr, len);

        let result_or_err = load_adl_internal(block_data);
        match result_or_err {
            Err(error) => {
                let res = Box::new(ADLorWAC {
                    err: byte_vec_to_byte_wrapper(error.to_string().as_bytes().to_owned()),
                    adl_ptr: std::ptr::null(),
                    adl_kind: 0,
                    wac: std::ptr::null(),
                });
                Box::into_raw(res)
            }
            Ok(val) => {
                let kind = match *val {
                    ReturnedValues::DirElem(elem) => match &*elem {
                        BTDirElem::Dir(_) => wac::WacCode::Map,
                        BTDirElem::File(_) => wac::WacCode::Bytes,
                    },
                    _ => {
                        let res = Box::new(ADLorWAC {
                            err: byte_vec_to_byte_wrapper(
                                "data was not file or directory".as_bytes().to_owned(),
                            ),
                            adl_ptr: std::ptr::null(),
                            adl_kind: 0,
                            wac: std::ptr::null(),
                        });
                        return Box::into_raw(res);
                    }
                };

                let res = Box::new(ADLorWAC {
                    err: std::ptr::null(),
                    adl_ptr: Box::into_raw(val) as *mut c_void,
                    adl_kind: kind.try_into().unwrap(),
                    wac: std::ptr::null(),
                });
                Box::into_raw(res)
            }
        }
    }

    /// Takes a pointer to an ADL and returns its length.
    ///
    /// # Safety
    ///
    /// This function assumes the adlptr is to a valid adl node
    unsafe fn adl_len(&self, adlptr: *const c_void) -> i64 {
        let adlptr_typed = adlptr as *const ReturnedValues;
        if let ReturnedValues::DirElem(elem) = *adlptr_typed {
            if let BTDirElem::Dir(d) = &*elem {
                let ret = d.children.len().try_into().unwrap();
                return ret;
            }
        }
        -1
    }

    /// Takes a pointer to an ADL as well as a buffer and its length
    /// and returns either an error, an ADL pointer, or WAC data.
    ///
    /// # Safety
    ///
    /// This function assumes the adl pointer is to a valid adl node.
    /// Also assumes the buffer pointer is to an allocated and usable buffer.
    unsafe fn get_key(
        &self,
        adlptr: *mut c_void,
        key_ptr: *mut u8,
        key_len: i32,
    ) -> *const ADLorWAC {
        let adlptr_typed = adlptr as *const ReturnedValues;
        if let ReturnedValues::DirElem(elem) = *adlptr_typed {
            if let BTDirElem::Dir(d) = &*elem {
                let key_len = key_len as usize;
                let key = ::std::slice::from_raw_parts(key_ptr, key_len);

                let res = get_key_safe(d, key);
                return match res {
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
                            adl_kind: 0,
                            wac: std::ptr::null(),
                        });
                        Box::into_raw(res)
                    }
                };
            }
        }

        let res = Box::new(ADLorWAC {
            err: byte_vec_to_byte_wrapper("data was not a directory".as_bytes().to_owned()),
            adl_ptr: std::ptr::null(),
            adl_kind: 0,
            wac: std::ptr::null(),
        });
        Box::into_raw(res)
    }

    /// # Safety
    ///
    /// This function assumes the adlptr is to a valid adl node
    unsafe fn new_map_iter(&self, adlptr: *const c_void) -> *mut c_void {
        let adlptr_typed = adlptr as *const ReturnedValues;
        if let ReturnedValues::DirElem(elem) = *adlptr_typed {
            if let BTDirElem::Dir(dir) = &*elem {
                let mut li: Vec<(*const String, *const BTDirElem)> = Vec::new();
                for (k, v) in &dir.children {
                    li.push((k, v))
                }

                let iter = DirectoryIter {
                    items: li,
                    index: 0,
                };

                let iter_box = Box::new(ReturnedValues::DirIter(iter));
                return Box::into_raw(iter_box) as *mut c_void;
            }
        }
        panic!("not a directory")
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
    unsafe fn iter_next(&self, adlptr: *mut c_void) -> *const IterResp {
        let adlptr_typed = adlptr as *const ReturnedValues;
        match &*adlptr_typed {
            ReturnedValues::DirIter(dir_iter) => {
                let next_item = dir_iter.items.get(dir_iter.index + 1);
                let ret = match next_item {
                    Some(kv_pair) => {
                        let kb = kv_pair.0.as_ref().unwrap().to_owned().into_bytes();
                        let elem = &*kv_pair.1;
                        let (ptr, kind) = match elem {
                            BTDirElem::Dir(d) => {
                                let ptr: *const BTDir = d;
                                (ptr as *const c_void, wac::WacCode::Map)
                            }
                            BTDirElem::File(f) => {
                                let ptr: *const BTFile = f;
                                (ptr as *const c_void, wac::WacCode::Bytes)
                            }
                        };

                        let res = Box::new(IterResp {
                            key: byte_vec_to_byte_wrapper(kb),
                            value_adl_ptr: ptr,
                            value_adl_kind: kind.into(),
                            val_wac: std::ptr::null(),
                            err: byte_vec_to_byte_wrapper("end of iterator".as_bytes().to_owned()),
                        });
                        res
                    }
                    None => {
                        let res = Box::new(IterResp {
                            key: std::ptr::null(),
                            value_adl_ptr: std::ptr::null(),
                            value_adl_kind: 0,
                            val_wac: std::ptr::null(),
                            err: byte_vec_to_byte_wrapper("end of iterator".as_bytes().to_owned()),
                        });
                        res
                    }
                };
                Box::into_raw(ret)
            }
            _ => panic!("not a map iter"),
        }
    }

    /// # Safety
    ///
    /// This function assumes the adlptr is to a valid adl node
    unsafe fn new_bytes_reader(&self, adlptr: *const c_void) -> *mut c_void {
        let adlptr_typed = adlptr as *const ReturnedValues;

        if let ReturnedValues::DirElem(elem) = *adlptr_typed {
            if let BTDirElem::File(f) = &*elem {
                let reader = FileReader {
                    file: f,
                    offset: 0,
                    length: (*f).length,
                };

                let reader_box = Box::new(ReturnedValues::Reader(reader));
                return Box::into_raw(reader_box) as *mut c_void;
            }
        }
        panic!("not bytes")
    }

    // Bytes

    /// Takes a pointer to an ADL along with the offset and whence enum.
    /// It returns the offset from the start of the data.
    ///
    /// Whence enum:
    /// 0 - seek relative to the origin of the file
    /// 1 - seek relative to the current offset
    /// 2 - seek relative to the end
    ///
    /// # Safety
    ///
    /// This function assumes the adlptr is to a valid adl node
    unsafe fn seek_adl(&self, adlptr: *mut c_void, offset: i64, whence: u32) -> u64 {
        let adlptr_typed = adlptr as *mut ReturnedValues;
        match &mut *adlptr_typed {
            ReturnedValues::Reader(r) => seek_adl_safe(r, offset, whence),
            _ => panic!("not a bytes reader"),
        }
    }

    /// Takes a pointer to an ADL as well as a buffer and its length
    /// and returns the number of bytes read.
    ///
    /// # Safety
    ///
    /// This function assumes the adl pointer is to a valid adl node.
    /// Also assumes the buffer pointer is to an allocated and usable buffer.
    unsafe fn read_adl(&self, adlptr: *mut u8, bufptr: *mut u8, bufleni: i32) -> *const ReadResp {
        let adlptr_typed = adlptr as *mut ReturnedValues;
        match &mut *adlptr_typed {
            ReturnedValues::Reader(r) => {
                // Get buffer
                let mut buf = Vec::from_raw_parts(
                    bufptr,
                    bufleni.try_into().unwrap(),
                    bufleni.try_into().unwrap(),
                );

                let fi_ptr = r.file;
                let fi = &*fi_ptr;
                // Read into the buffer
                let res = read_adl_safer(r, fi, &mut buf);

                // Release the buffer
                let b_buf = Box::new(buf);
                Box::leak(b_buf);

                match res {
                    Ok(v) => {
                        let bx = Box::new(ReadResp {
                            bytes_read: v,
                            err: std::ptr::null(),
                        });
                        Box::into_raw(bx)
                    }
                    Err(err) => {
                        let bx = Box::new(ReadResp {
                            bytes_read: 0,
                            err: byte_vec_to_byte_wrapper(err.to_string().as_bytes().to_owned()),
                        });
                        Box::into_raw(bx)
                    }
                }
            }
            _ => {
                let bx = Box::new(ReadResp {
                    bytes_read: 0,
                    err: byte_vec_to_byte_wrapper("not a reader".as_bytes().to_owned()),
                });
                Box::into_raw(bx)
            }
        }
    }
}

impl helpers::AdlBase for BtAdl {
    unsafe fn load_adl(&self, ptr: *mut u8, len: u32) -> *mut ADLorWAC {
        self.load_adl(ptr, len)
    }
}

impl helpers::AdlBytes for BtAdl {
    unsafe fn new_bytes_reader(&self, adlptr: *const c_void) -> *mut c_void {
        self.new_bytes_reader(adlptr)
    }

    unsafe fn read_adl(&self, adlptr: *mut u8, bufptr: *mut u8, bufleni: i32) -> *const ReadResp {
        self.read_adl(adlptr, bufptr, bufleni)
    }

    unsafe fn seek_adl(&self, adlptr: *mut c_void, offset: i64, whence: u32) -> u64 {
        self.seek_adl(adlptr, offset, whence)
    }
}

impl helpers::AdlMap for BtAdl {
    unsafe fn new_map_iter(&self, adlptr: *const c_void) -> *mut c_void {
        self.new_map_iter(adlptr)
    }

    unsafe fn iter_next(&self, adlptr: *mut c_void) -> *const IterResp {
        self.iter_next(adlptr)
    }

    unsafe fn get_key(
        &self,
        adlptr: *mut c_void,
        key_ptr: *mut u8,
        key_len: i32,
    ) -> *const ADLorWAC {
        self.get_key(adlptr, key_ptr, key_len)
    }

    unsafe fn adl_len(&self, adlptr: *const c_void) -> i64 {
        self.adl_len(adlptr)
    }
}

fn get_key_safe(dir: &BTDir, key_bytes: &[u8]) -> Result<Box<ADLorWAC>, libipld::error::Error> {
    let key = std::str::from_utf8(key_bytes)?;
    dir_get_key(dir, key)
}

fn dir_get_key(dir: &BTDir, key: &str) -> Result<Box<ADLorWAC>, libipld::error::Error> {
    let val = dir
        .children
        .get(key)
        .ok_or_else(|| libipld::error::Error::msg("not found"))?;

    let val_kind = match val {
        BTDirElem::File(_) => wac::WacCode::Bytes,
        BTDirElem::Dir(_) => wac::WacCode::Map,
    };

    let val_ptr = Box::into_raw(Box::new(ReturnedValues::DirElem(val)));
    Ok(Box::new(ADLorWAC {
        err: std::ptr::null(),
        adl_ptr: val_ptr as *const c_void,
        adl_kind: val_kind.into(),
        wac: std::ptr::null(),
    }))
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

fn read_adl_safer(
    f: &mut FileReader,
    file_info: &BTFile,
    buf: &mut [u8],
) -> Result<u32, libipld::error::Error> {
    let buflen = buf.len() as u32;

    // skip if past the end
    if f.offset == f.length {
        return Err(libipld::error::Error::msg("read: EOF"));
    }
    if f.offset > f.length {
        return Err(libipld::error::Error::msg(
            "tried reading past the end of the file",
        ));
    }

    let mut bufrem = buflen;

    // handle the first block
    let mut piece_num = ((f.offset + file_info.start_offset) / file_info.piece_length) as usize;
    let start_delta = ((f.offset + file_info.start_offset) % file_info.piece_length) as usize;
    let mut at = f.offset;

    while at < f.length && bufrem > 0 {
        // fastforward the first one if needed.
        let blk_cid = file_info.pieces[piece_num];
        let block_data: Box<[u8]>;

        unsafe {
            block_data = load_raw_block_caller(blk_cid)?;
        }

        if at == f.offset {
            let mut num_to_copy = bufrem;
            if (num_to_copy as u64) > f.length - at {
                num_to_copy = (f.length - at) as u32
            }
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
            if (num_to_copy as u64) > f.length - at {
                num_to_copy = (f.length - at) as u32
            }
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
    Ok(num_read)
}

fn load_adl_internal(input: &[u8]) -> Result<Box<ReturnedValues>, Error> {
    // Assume node is WAC
    let node = wac::from_bytes(input)?;

    let node_map = wac::ipld_try_map(node)?;

    let pieces_node = node_map
        .get("pieces".as_bytes())
        .ok_or_else(|| libipld::error::Error::msg("pieces not in node"))?;
    let pieces_bytes = wac::ipld_try_bytestring(pieces_node.to_owned())?;

    const SHA1_HASH_LEN: usize = 20;
    if pieces_bytes.len() % SHA1_HASH_LEN != 0 {
        return Err(libipld::error::Error::msg(
            "pieces string is not a multiple of 20 bytes",
        ));
    }

    let piece_length_node = node_map
        .get("piece length".as_bytes())
        .ok_or_else(|| libipld::error::Error::msg("piece length not in node"))?;
    let piece_length_int = wac::ipld_try_int(piece_length_node.to_owned())?;

    let mut pieces: Vec<libipld::Cid> = Vec::new();
    for c in pieces_bytes.chunks_exact(SHA1_HASH_LEN) {
        let mh = Multihash::wrap(0x11, c)?;
        let cid = CidGeneric::new_v1(0x55, mh);
        pieces.push(cid);
    }

    // check if file or directory
    let file_len = node_map.get("length".as_bytes());
    if let Some(len) = file_len {
        if node_map.contains_key("files".as_bytes()) {
            return Err(libipld::error::Error::msg(
                "cannot contain both length and files fields",
            ));
        }

        let len_int: u64 = wac::ipld_try_int(len.to_owned())?.try_into()?;
        let file = BTFile {
            start_offset: 0,
            pieces,
            length: len_int,
            piece_length: piece_length_int.try_into()?,
        };

        let f_elem = Box::into_raw(Box::new(BTDirElem::File(file)));
        let fb: Box<ReturnedValues> = Box::new(ReturnedValues::DirElem(f_elem));
        return Ok(fb);
    }

    let files_list = node_map
        .get("files".as_bytes())
        .ok_or_else(|| libipld::error::Error::msg("files not in node"))?;
    let files_list = wac::ipld_try_list(files_list.to_owned())?;

    let mut dir = BTDir {
        children: BTreeMap::new(),
    };

    let mut start_piece = 0;
    let mut start_index = 0;
    // Do validation
    for f_dict in files_list {
        let d = wac::ipld_try_map(f_dict)?;
        let path_segs = d
            .get("path".as_bytes())
            .ok_or_else(|| libipld::error::Error::msg("path not in node"))?;
        let path_segs = wac::ipld_try_list(path_segs.to_owned())?;
        let mut internal_dir = dir.borrow_mut();
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
                    .and_then(|w| wac::ipld_try_int(w.to_owned()).ok())
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
                start_piece = start_piece + num_pieces - 1;
                if start_index == 0 {
                    start_piece += 1;
                }
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

    let d_elem = Box::into_raw(Box::new(BTDirElem::Dir(dir)));
    let db: Box<ReturnedValues> = Box::new(ReturnedValues::DirElem(d_elem));
    Ok(db)
}

struct FileReader {
    file: *const BTFile,
    offset: u64,
    length: u64,
}

enum BTDirElem {
    Dir(BTDir),
    File(BTFile),
}

enum ReturnedValues {
    DirElem(*const BTDirElem),
    Reader(FileReader),
    DirIter(DirectoryIter),
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

struct DirectoryIter {
    items: Vec<(*const String, *const BTDirElem)>,
    index: usize,
}

#[cfg(test)]
mod tests {
    use std::{ffi::c_void, str::FromStr};

    use crate::{get_key, load_adl, new_bytes_reader, read_adl, seek_adl};
    use helpers::ByteWrapper;
    use libipld::{Cid, Multihash};

    unsafe fn assert_no_err(err: *const ByteWrapper) {
        if !err.is_null() {
            let e = &*err;
            let err_slice = std::slice::from_raw_parts(e.msg_ptr, e.msg_len.try_into().unwrap());
            let err_str = std::str::from_utf8(err_slice).expect("non-utf8 error");
            panic!("{}", err_str)
        }
    }

    #[test]
    fn test_dir_elem() {
        {
            let mut m = helpers::global_blocks::GLOBAL_BLOCKSTORE.lock().unwrap();
            let block1 = include_bytes!("../../bittorrent-fixtures/animals-fixtures/blocks/f0155111413da56fd10d288769fdea62d464572c5f16e967d.blk");
            let c1 = Cid::from_str("f0155111413da56fd10d288769fdea62d464572c5f16e967d").unwrap();
            m.insert(c1, block1);
            let block1 = include_bytes!("../../bittorrent-fixtures/animals-fixtures/blocks/f01551114dc462b4d35419ca9230d69d758f0832a30959baa.blk");
            let c1 = Cid::from_str("f01551114dc462b4d35419ca9230d69d758f0832a30959baa").unwrap();
            m.insert(c1, block1);
        }
        let hex_wac_file_root = "0904060566696c65730802090206066c656e6774680392d510060470617468080106094b6f616c612e6a7067090206066c656e67746803a6dc050604706174680801060970616e64612e6a706706046e616d650607616e696d616c73060c7069656365206c656e677468038080100606706965636573062813da56fd10d288769fdea62d464572c5f16e967ddc462b4d35419ca9230d69d758f0832a30959baa";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr_or_err = &*load_adl(
                wac_file_root.as_mut_ptr(),
                wac_file_root.len().try_into().unwrap(),
            );
            assert_no_err(adl_ptr_or_err.err);
            let adl_ptr = adl_ptr_or_err.adl_ptr as *mut c_void;
            let adl_kind: u8 = wac::WacCode::Map.into();
            assert_eq!(adl_ptr_or_err.adl_kind, adl_kind);

            let lookup_key = "Koala.jpg";
            let lookup_res = &*get_key(
                adl_ptr,
                lookup_key.as_ptr() as *mut u8,
                lookup_key.len().try_into().unwrap(),
            );
            assert_no_err(lookup_res.err);
            let adl_kind: u8 = wac::WacCode::Bytes.into();
            assert_eq!(lookup_res.adl_kind, adl_kind);

            let file_reader_ptr = new_bytes_reader(lookup_res.adl_ptr);

            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(1024 * 1024, 0);

            let resp = read_adl(
                file_reader_ptr as *mut u8,
                buffer.as_mut_ptr(),
                buffer.len() as i32,
            );
            assert_eq!((*resp).err, std::ptr::null());
            let num_read = (*resp).bytes_read;
            assert_eq!(num_read, 273042);
            buffer.truncate(num_read.try_into().unwrap());

            let raw_file =
                include_bytes!("../../bittorrent-fixtures/animals-fixtures/animals/Koala.jpg");
            assert_eq!(buffer.as_slice(), raw_file);
        }
    }

    #[test]
    fn test_full_read() {
        {
            let mut m = helpers::global_blocks::GLOBAL_BLOCKSTORE.lock().unwrap();

            let dig1 = hex::decode("38666b8ba500faa5c2406f4575d42a92379844c2").unwrap();
            let blk1: &[u8] = &[0x61; 30];
            let mh1 = Multihash::wrap(0x11, &dig1).unwrap();
            m.insert(libipld::Cid::new_v1(0x55, mh1), blk1);

            let dig2 = hex::decode("45dfb79d668374f6578b3128746dce59b7a02e80").unwrap();
            let blk2: &[u8] = &[0x62; 10];
            let mh2 = Multihash::wrap(0x11, &dig2).unwrap();
            m.insert(libipld::Cid::new_v1(0x55, mh2), blk2);
        }

        let hex_wac_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr_or_err = &*load_adl(wac_file_root.as_mut_ptr(), wac_file_root.len() as u32);
            assert_no_err(adl_ptr_or_err.err);
            let adl_ptr = adl_ptr_or_err.adl_ptr as *mut c_void;
            let adl_kind: u8 = wac::WacCode::Bytes.into();
            assert_eq!(adl_ptr_or_err.adl_kind, adl_kind);

            let adl_ptr = new_bytes_reader(adl_ptr);

            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(40, 0);

            let read_resp = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!((*read_resp).err, std::ptr::null());
            let num_read = (*read_resp).bytes_read;

            assert_eq!(num_read, 40);
            assert_eq!(buffer.as_slice()[0..30], [0x61; 30]);
            assert_eq!(buffer.as_slice()[30..], [0x62; 10]);
        }
    }

    #[test]
    fn test_partial_reads() {
        {
            let mut m = helpers::global_blocks::GLOBAL_BLOCKSTORE.lock().unwrap();

            let dig1 = hex::decode("38666b8ba500faa5c2406f4575d42a92379844c2").unwrap();
            let blk1: &[u8] = &[0x61; 30];
            let mh1 = Multihash::wrap(0x11, &dig1).unwrap();
            m.insert(libipld::Cid::new_v1(0x55, mh1), blk1);

            let dig2 = hex::decode("45dfb79d668374f6578b3128746dce59b7a02e80").unwrap();
            let blk2: &[u8] = &[0x62; 10];
            let mh2 = Multihash::wrap(0x11, &dig2).unwrap();
            m.insert(libipld::Cid::new_v1(0x55, mh2), blk2);
        }

        let hex_wac_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr_or_err = &*load_adl(wac_file_root.as_mut_ptr(), wac_file_root.len() as u32);
            assert_no_err(adl_ptr_or_err.err);
            let adl_ptr = adl_ptr_or_err.adl_ptr as *mut c_void;
            let adl_kind: u8 = wac::WacCode::Bytes.into();
            assert_eq!(adl_ptr_or_err.adl_kind, adl_kind);

            let adl_ptr = new_bytes_reader(adl_ptr);

            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(20, 0);

            let read_resp = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!((*read_resp).err, std::ptr::null());
            let num_read = (*read_resp).bytes_read;
            assert_eq!(num_read, 20);
            assert_eq!(buffer.as_slice()[0..20], [0x61; 20]);

            let read_resp = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!((*read_resp).err, std::ptr::null());
            let num_read = (*read_resp).bytes_read;
            assert_eq!(num_read, 20);
            assert_eq!(buffer.as_slice()[0..10], [0x61; 10]);
            assert_eq!(buffer.as_slice()[10..], [0x62; 10]);
        }
    }

    #[test]
    fn test_seek_read() {
        {
            let mut m = helpers::global_blocks::GLOBAL_BLOCKSTORE.lock().unwrap();

            let dig1 = hex::decode("38666b8ba500faa5c2406f4575d42a92379844c2").unwrap();
            let blk1: &[u8] = &[0x61; 30];
            let mh1 = Multihash::wrap(0x11, &dig1).unwrap();
            m.insert(libipld::Cid::new_v1(0x55, mh1), blk1);

            let dig2 = hex::decode("45dfb79d668374f6578b3128746dce59b7a02e80").unwrap();
            let blk2: &[u8] = &[0x62; 10];
            let mh2 = Multihash::wrap(0x11, &dig2).unwrap();
            m.insert(libipld::Cid::new_v1(0x55, mh2), blk2);
        }

        let hex_wac_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr_or_err = &*load_adl(wac_file_root.as_mut_ptr(), wac_file_root.len() as u32);
            assert_no_err(adl_ptr_or_err.err);
            let adl_ptr = adl_ptr_or_err.adl_ptr as *mut c_void;
            let adl_kind: u8 = wac::WacCode::Bytes.into();
            assert_eq!(adl_ptr_or_err.adl_kind, adl_kind);

            let adl_ptr = new_bytes_reader(adl_ptr);

            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(20, 0);

            let seek_to = seek_adl(adl_ptr, 15, 0);
            assert_eq!(seek_to, 15);

            let read_resp = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!((*read_resp).err, std::ptr::null());
            let num_read = (*read_resp).bytes_read;
            assert_eq!(num_read, 20);
            assert_eq!(buffer.as_slice()[0..15], [0x61; 15]);
            assert_eq!(buffer.as_slice()[15..], [0x62; 5]);
        }
    }
}
