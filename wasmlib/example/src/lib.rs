/*

Items still unclear:
- What to do about 32 vs 64 bit? Do we just define everything as 32 bit until 64 bit wasm is everywhere?
- How to free memory, both that used by the host to pass data in and for data returned (e.g. strings)
- If/how we allow multiple modules to work together without going through the host
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
pub struct ByteWrapper {
    pub msg_len: u32,
    pub msg_ptr: *const u8,
}

#[repr(C)]
pub struct ADLorWAC {
    pub err: *const ByteWrapper,
    pub adl_ptr: *const c_void,
    pub wac: *const ByteWrapper,
}

#[repr(C)]
pub struct IterResp {
    pub err: *const ByteWrapper,
    pub key: *const ByteWrapper,
    pub value_adl_ptr: *const c_void,
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
    fn load_raw_block(cid_bytes: *const u8, cid_length: u8) -> *const ValueOrError;
}

#[cfg(target_arch = "wasm32")]
extern "C" {
    fn load_wac_block(cid_bytes: *const u8, cid_length: u8) -> *const ValueOrError;
}

#[cfg(not(target_arch = "wasm32"))]
fn load_raw_block(cid_bytes: *const u8, cid_length: u8) -> *const ValueOrError {
    let c_bytes;
    unsafe {
        c_bytes = ::std::slice::from_raw_parts(cid_bytes, cid_length as usize);
    }
    let cr = Cid::read_bytes(c_bytes).expect("could not load cid");

    let m = global_blocks::GLOBAL_BLOCKSTORE.lock().unwrap();
    let val = m.get(&cr).expect("could not load block");
    get_result_bytes(Ok(val.to_vec()))
}

#[cfg(not(target_arch = "wasm32"))]
fn load_wac_block(cid_bytes: *const u8, cid_length: u8) -> *const ValueOrError {
    let c_bytes;
    unsafe {
        c_bytes = ::std::slice::from_raw_parts(cid_bytes, cid_length as usize);
    }
    let cr = Cid::read_bytes(c_bytes).expect("could not load cid");

    let m = global_blocks::GLOBAL_WAC_BLOCKSTORE.lock().unwrap();
    let val = m.get(&cr).expect("could not load block");
    get_result_bytes(Ok(val.to_vec()))
}

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
        Ok(v) => {
            let blk_wrapped = &*(v as *const ByteWrapper);
            let block_data =
                ::std::slice::from_raw_parts(blk_wrapped.msg_ptr, blk_wrapped.msg_len as usize);
            Ok(block_data.to_owned().into_boxed_slice())
        }
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
        Ok(v) => {
            let blk_wrapped = &*(v as *const ByteWrapper);
            let block_data =
                ::std::slice::from_raw_parts(blk_wrapped.msg_ptr, blk_wrapped.msg_len as usize);
            Ok(block_data.to_owned().into_boxed_slice())
        }
        Err(err) => Err(err),
    }
}

/*

use std::any::Any;

All returned data structures

/// Given a pointer to the start of a byte array of WAC data
/// encode the data into the codec
///
///
/// # Safety
///
/// This function assumes the block pointer has size have been allocated and filled.
#[no_mangle]
pub unsafe fn encode(ptr: *mut u8, len: u32) -> *const ValueOrError {
    let len = len as usize;
    let data = ::std::slice::from_raw_parts(ptr, len);

    let result : Result<Vec<u8>, libipld::error::Error> = encode_safe(data);

    get_result_bytes(result)
}

fn encode_safe(blk : &[u8]) -> Result<Vec<u8>, libipld::error::Error> {
    return Ok(blk.to_vec())
}

/// Given a pointer to the start of a byte array and
/// its length, decode it into a standard IPLD codec representation
/// (for now WAC)
///
/// # Safety
///
/// This function assumes the block pointer has size have been allocated and filled.
#[no_mangle]
pub unsafe fn decode(ptr: *mut u8, len: u32) -> *const ValueOrError {
    let len = len as usize;
    let data = ::std::slice::from_raw_parts(ptr, len);
    let result = decode_safe(data);

    get_result_bytes(result)
}

fn decode_safe(blk : &[u8]) -> Result<Vec<u8>, libipld::error::Error> {
    return Ok(blk.to_vec())
}

// ADLs

/*
    ADL pointers should be able to specify both the data and the type
    such that the host caller doesn't need to change function names depending on the type

    An example might be returning *mut dyn Any and then downcasting to the relevant type or leveraging TypeIds
*/

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

    let result_or_err = load_adl_safe(block_data);
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

fn load_adl_safe(blk : &[u8]) -> Result<*const u8, libipld::error::Error> {
    let b : Box<dyn Any> = Box::new(blk.clone().to_owned());
    return Ok(Box::into_raw(b) as *const u8)
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
    let mut fb = Box::from_raw(adlptr as *mut dyn Any);

    // Release ADL memory
    // Box::leak(fb);

    0
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
    // Get and type check ADL

    // Get buffer
    let mut buf = Vec::from_raw_parts(
        bufptr,
        bufleni.try_into().unwrap(),
        bufleni.try_into().unwrap(),
    );

    // Read into the buffer
    //let res = read_adl_safer(fb.as_mut(), &mut buf);
    let res = 0;

    // Release ADL
    //Box::leak(fb);
    let b_buf = Box::new(buf);
    // Release buffer
    Box::leak(b_buf);
    res
}

// Other Scalars (no "large versions")

/// Takes a pointer to an ADL and returns a pointer to its WAC encoding
///
/// TODO: Allow returning an error
/// TODO: Is it worth having more efficient paths for bool, null and int? Seems unlikely given they're unlikely to be used
/// TODO: Do we need BigInt? Should we bother with any of these until they're needed?
///
/// # Safety
///
/// This function assumes the adl pointer is to a valid adl node.
/// Also assumes the buffer pointer is to an allocated and usable buffer.
#[no_mangle]
pub unsafe fn adl_get_generic(adlptr: *mut u8) -> *const u8 {
    // Get ADL
    //let mut fb = Box::from_raw(adlptr as *mut FileReader);

    // Read into the buffer
    //let res = adl_bool_safer(fb.as_mut(), &mut buf);
    let res = std::ptr::null();

    // Release ADL
    //Box::leak(fb);
    res
}

// Recursive Types

/// Takes a pointer to an ADL and returns its length.
///
/// TODO: Should we allow returning an error?
///
/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn adl_len(adlptr: *mut u8) -> i64 {
    0
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
pub unsafe fn get_index(adlptr: *mut u8, index: i32) -> *const ADLorWAC {

}

/// Takes a pointer to an ADL and returns a new map iterator over it.
///
/// TODO: Should we allow returning an error?
/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn new_map_iter(adlptr: *mut u8) -> *const ValueOrError {
}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn iter_next(adlptr: *mut u8) -> *const ADLorWAC {
}

/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn iter_done(adlptr: *mut u8) -> *const BoolOrError {
}

/// Takes a pointer to an ADL and returns a new map iterator over it.
///
/// TODO: Should we allow returning an error?
/// # Safety
///
/// This function assumes the adlptr is to a valid adl node
#[no_mangle]
pub unsafe fn new_list_iter(adlptr: *mut u8) -> *const ValueOrError {
}

*/

use std::ffi::c_void;

use libipld::Cid;
