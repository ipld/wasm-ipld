/*
Items still unclear:
- What to do about 32 vs 64 bit? Do we just define everything as 32 bit until 64 bit wasm is everywhere?
- How to free memory, both that used by the host to pass data in and for data returned (e.g. strings)
- If/how we allow multiple modules to work together without going through the host
- How to make it easy for someone to make a compatible WASM module
*/

/// Allocate memory into the module's linear memory
/// and return the offset to the start of the block.
#[no_mangle]
pub fn myalloc(len: usize) -> *mut u8 {
    let buf = vec![0u8; len];
    Box::leak(buf.into_boxed_slice()).as_mut_ptr()
}

#[repr(C)]
pub struct ValueOrError {
    pub err: *const ByteWrapper,
    pub value: *mut c_void,
}

impl ValueOrError {
    /// Turn the data into a result which is either a pointer or an error
    ///
    /// # Safety
    ///
    /// This function assumes each of the pointers are either nil or valid
    pub unsafe fn to_result(&self) -> Result<*mut c_void, libipld::error::Error> {
        if !self.err.is_null() {
            let err = &*self.err;
            let msg = ::std::slice::from_raw_parts(err.msg_ptr, err.msg_len.try_into().unwrap());
            let msg_str = std::str::from_utf8(msg)?;
            return Err(libipld::error::Error::msg(msg_str));
        }
        Ok(self.value)
    }
}

#[repr(C)]
pub struct BlockResp {
    pub msg_len: u32,
    pub msg_ptr: *const u8,
    pub is_err: bool,
}

impl BlockResp {
    /// Turn the data into a result which is either bytes or an error
    ///
    /// # Safety
    ///
    /// This function assumes each of the pointers are either nil or valid
    pub unsafe fn to_result(&self) -> Result<&[u8], libipld::error::Error> {
        let msg = ::std::slice::from_raw_parts(self.msg_ptr, self.msg_len.try_into().unwrap());
        if self.is_err {
            let msg_str = std::str::from_utf8(msg)?;
            return Err(libipld::error::Error::msg(msg_str));
        }
        Ok(msg)
    }
}

#[repr(C)]
pub struct ByteWrapper {
    pub msg_len: u32,
    pub msg_ptr: *const u8,
}

#[repr(C)]
pub struct ADLorWAC {
    pub err: *const ByteWrapper,
    pub adl_ptr: *const c_void,
    pub adl_kind: u8,
    pub wac: *const ByteWrapper,
}

#[repr(C)]
pub struct IterResp {
    pub err: *const ByteWrapper,
    pub key: *const ByteWrapper,
    pub value_adl_ptr: *const c_void,
    pub value_adl_kind: u8,
    pub val_wac: *const ByteWrapper,
}

#[repr(C)]
pub struct ReadResp {
    pub err: *const ByteWrapper,
    pub bytes_read: u32,
}

#[repr(C)]
pub struct BoolOrError {
    pub err: *const ByteWrapper,
    pub value: bool,
}

pub fn byte_vec_to_byte_wrapper(b: Vec<u8>) -> *const ByteWrapper {
    let bx = b.into_boxed_slice();
    let bx_len = bx.len() as u32;
    let bytes_ptr = Box::into_raw(bx) as *const u8;

    Box::into_raw(Box::new(ByteWrapper {
        msg_len: bx_len,
        msg_ptr: bytes_ptr,
    }))
}

pub fn get_error(err: libipld::error::Error) -> *const ValueOrError {
    let res = Box::new(ValueOrError {
        value: std::ptr::null::<c_void>() as *mut c_void,
        err: byte_vec_to_byte_wrapper(err.to_string().as_bytes().to_owned()),
    });
    Box::into_raw(res)
}

pub fn get_result_bytes(result: Result<Vec<u8>, libipld::error::Error>) -> *const ValueOrError {
    match result {
        Ok(v) => {
            let bx = v.into_boxed_slice();
            let bx_len = bx.len() as u32;
            let bytes_ptr = Box::into_raw(bx) as *const u8;

            let res = Box::new(ValueOrError {
                err: std::ptr::null(),
                value: Box::into_raw(Box::new(ByteWrapper {
                    msg_len: bx_len,
                    msg_ptr: bytes_ptr,
                })) as *mut c_void,
            });
            Box::into_raw(res)
        }
        Err(err) => get_error(err),
    }
}

// Extern Functions

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn load_raw_block(cid_bytes: *const u8, cid_length: u8) -> *const BlockResp;
}

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn load_wac_block(cid_bytes: *const u8, cid_length: u8) -> *const BlockResp;
}

// Used for testing and matching the wasm extern function
#[cfg(not(target_arch = "wasm32"))]
fn load_raw_block(cid_bytes: *const u8, cid_length: u8) -> *const BlockResp {
    let c_bytes;
    unsafe {
        c_bytes = ::std::slice::from_raw_parts(cid_bytes, cid_length as usize);
    }
    let cr = Cid::read_bytes(c_bytes).expect("could not load cid");

    let m = global_blocks::GLOBAL_BLOCKSTORE.lock().unwrap();
    let val = m.get(&cr).expect("could not load block");

    let bx = val.to_vec().into_boxed_slice();
    let bx_len = bx.len() as u32;
    let bytes_ptr = Box::into_raw(bx) as *const u8;

    let res = Box::new(BlockResp {
        msg_len: bx_len,
        msg_ptr: bytes_ptr,
        is_err: false,
    });
    Box::into_raw(res)
}

// Used for testing and matching the wasm extern function
#[cfg(not(target_arch = "wasm32"))]
fn load_wac_block(cid_bytes: *const u8, cid_length: u8) -> *const BlockResp {
    let c_bytes;
    unsafe {
        c_bytes = ::std::slice::from_raw_parts(cid_bytes, cid_length as usize);
    }
    let cr = Cid::read_bytes(c_bytes).expect("could not load cid");

    let m = global_blocks::GLOBAL_WAC_BLOCKSTORE.lock().unwrap();
    let val = m.get(&cr).expect("could not load block");

    let bx = val.to_vec().into_boxed_slice();
    let bx_len = bx.len() as u32;
    let bytes_ptr = Box::into_raw(bx) as *const u8;

    let res = Box::new(BlockResp {
        msg_len: bx_len,
        msg_ptr: bytes_ptr,
        is_err: false,
    });
    Box::into_raw(res)
}

// Used for testing and matching the wasm extern function
#[cfg(not(target_arch = "wasm32"))]
pub mod global_blocks {
    use std::{collections::HashMap, sync::Mutex};

    use libipld::Cid;
    use once_cell::sync::Lazy;

    pub static GLOBAL_BLOCKSTORE: Lazy<Mutex<HashMap<Cid, &[u8]>>> = Lazy::new(|| {
        let m = HashMap::new();
        Mutex::new(m)
    });

    pub static GLOBAL_WAC_BLOCKSTORE: Lazy<Mutex<HashMap<Cid, &[u8]>>> = Lazy::new(|| {
        let m = HashMap::new();
        Mutex::new(m)
    });
}

/// Given a pointer to the start of a byte array of WAC data
/// encode the data into the codec
///
///
/// # Safety
///
/// This function assumes that the load_raw_block function returns valid results
pub unsafe fn load_raw_block_caller(blk_cid: Cid) -> Result<Box<[u8]>, libipld::error::Error> {
    let blk_cid_bytes = blk_cid.to_bytes();
    let cidptr = blk_cid_bytes.as_ptr();

    let blk_res = &*load_raw_block(cidptr, blk_cid_bytes.len() as u8);
    let res = blk_res.to_result();
    match res {
        Ok(v) => Ok(v.to_owned().into_boxed_slice()),
        Err(err) => Err(err),
    }
}

/// Given a pointer to the start of a byte array of WAC data
/// encode the data into the codec
///
///
/// # Safety
///
/// This function assumes that the load_raw_block function returns valid results
pub unsafe fn load_wac_block_caller(blk_cid: Cid) -> Result<Box<[u8]>, libipld::error::Error> {
    let blk_cid_bytes = blk_cid.to_bytes();
    let cidptr = blk_cid_bytes.as_ptr();

    let blk_res = &*load_wac_block(cidptr, blk_cid_bytes.len() as u8);
    let res = blk_res.to_result();
    match res {
        Ok(v) => Ok(v.to_owned().into_boxed_slice()),
        Err(err) => Err(err),
    }
}

use std::ffi::c_void;

use libipld::Cid;

pub trait Codec {
    /// Given a pointer to the start of a byte array of WAC data
    /// encode the data into the codec
    ///
    /// # Safety
    ///
    /// This function assumes the block pointer has size have been allocated and filled.
    unsafe fn encode(&self, ptr: *mut u8, len: u32) -> *const ValueOrError;

    /// Given a pointer to the start of a byte array and
    /// its length, decode it into a standard IPLD codec representation
    /// (for now WAC)
    ///
    /// # Safety
    ///
    /// This function assumes the block pointer has size have been allocated and filled.
    unsafe fn decode(&self, ptr: *mut u8, len: u32) -> *const ValueOrError;
}

pub trait AdlBase {
    /// Takes a pointer and length of a byte array containing WAC encoded data and returns
    /// a pointer to the ADL instance.
    ///
    /// # Safety
    ///
    /// This function assumes the block pointer has size have been allocated and filled.
    unsafe fn load_adl(&self, ptr: *mut u8, len: u32) -> *mut ADLorWAC;
}

#[allow(clippy::missing_safety_doc)]
pub trait AdlBytes {
    unsafe fn new_bytes_reader(&self, adlptr: *const c_void) -> *mut c_void;
    unsafe fn read_adl(&self, adlptr: *mut u8, bufptr: *mut u8, bufleni: i32) -> *const ReadResp;
    unsafe fn seek_adl(&self, adlptr: *mut c_void, offset: i64, whence: u32) -> u64;
}

#[allow(clippy::missing_safety_doc)]
pub trait AdlMap {
    unsafe fn new_map_iter(&self, adlptr: *const c_void) -> *mut c_void;
    unsafe fn iter_next(&self, adlptr: *mut c_void) -> *const IterResp;
    unsafe fn get_key(
        &self,
        adlptr: *mut c_void,
        key_ptr: *mut u8,
        key_len: i32,
    ) -> *const ADLorWAC;
    unsafe fn adl_len(&self, adlptr: *const c_void) -> i64;
}

// unsafe fn iter_done(adlptr: *mut u8) -> *const BoolOrError;

#[allow(clippy::missing_safety_doc)]
pub trait AdlList {
    unsafe fn get_index(&self, adlptr: *mut u8, index: i32) -> *const ADLorWAC;
    unsafe fn new_list_iter(&self, adlptr: *mut u8) -> *const ValueOrError;
    unsafe fn iter_next(&self, adlptr: *mut c_void) -> *const IterResp;
    unsafe fn adl_len(&self, adlptr: *const c_void) -> i64;
}

/*
/// Given a pointer to the start of a byte array of WAC data
/// encode the data into the codec
///
/// # Safety
///
/// This function assumes the block pointer has size have been allocated and filled.
#[no_mangle]
pub unsafe fn encode(ptr: *mut u8, len: u32) -> *const ValueOrError {}

/// Given a pointer to the start of a byte array and
/// its length, decode it into a standard IPLD codec representation
/// (for now WAC)
///
/// # Safety
///
/// This function assumes the block pointer has size have been allocated and filled.
#[no_mangle]
pub unsafe fn decode(ptr: *mut u8, len: u32) -> *const ValueOrError {}

/// Takes a pointer and length of a byte array containing WAC encoded data and returns
/// a pointer to the ADL instance.
///
/// # Safety
///
/// This function assumes the block pointer has size have been allocated and filled.
#[no_mangle]
pub unsafe fn load_adl(ptr: *mut u8, len: u32) -> *mut ADLorWAC {}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn new_bytes_reader(adlptr: *const c_void) -> *mut c_void {}

/// Takes a pointer to an ADL as well as a buffer and its length
/// and returns the number of bytes read.
///
/// # Safety
///
/// This function assumes the adl pointer is to a valid adl node.
/// Also assumes the buffer pointer is to an allocated and usable buffer.
#[no_mangle]
pub unsafe fn read_adl(adlptr: *mut u8, bufptr: *mut u8, bufleni: i32) -> *const ReadResp {}

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
pub unsafe fn seek_adl(adlptr: *mut c_void, offset: i64, whence: u32) -> u64 {}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn new_map_iter(adlptr: *const c_void) -> *mut c_void {}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn iter_next(adlptr: *mut c_void) -> *const IterResp {}

/// Takes a pointer to an ADL as well as a buffer and its length
/// and returns either an error, an ADL pointer, or WAC data.
///
/// # Safety
///
/// This function assumes the adl pointer is to a valid adl node.
/// Also assumes the buffer pointer is to an allocated and usable buffer.
#[no_mangle]
pub unsafe fn get_key(adlptr: *mut c_void, key_ptr: *mut u8, key_len: i32) -> *const ADLorWAC {}

/// Takes a pointer to an ADL and returns its length.
///
/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn adl_len(adlptr: *const c_void) -> i64 {}
*/
