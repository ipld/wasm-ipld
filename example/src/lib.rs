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
    err: *const ByteWrapper,
    value: *mut u8
}

#[repr(C)]
pub struct ByteWrapper {
    msg_len: u32,
    msg_ptr: *const u8,
}

#[repr(C)]
pub struct ADLorWAC {
    err: *const ByteWrapper,
    adl_ptr: *const u8,
    wac : *const ByteWrapper,
}

#[repr(C)]
pub struct BoolOrError {
    err: *const ByteWrapper,
    value: bool
}

fn get_error(err : libipld::error::Error) -> *const ValueOrError {
    let errStr = err.to_string().as_bytes().to_owned();
    let bx = errStr.into_boxed_slice();
    let bytes_ptr = Box::into_raw(bx) as *const u8;

    let res = Box::new(ValueOrError {
        value : std::ptr::null::<u8>() as *mut u8,
        err : Box::into_raw(
            Box::new(ByteWrapper {
        msg_len : bx.len() as u32,
        msg_ptr : bytes_ptr,
    })
        ),
    });
    Box::into_raw(res)
}

fn get_result_bytes(result : Result<Vec<u8>, libipld::error::Error>) -> *const ValueOrError {
    match result {
        Ok(v) => {
            let bx = v.into_boxed_slice();
            let bytes_ptr = Box::into_raw(bx) as *const u8;
            
            let res = Box::new(ValueOrError {
                err : std::ptr::null(),
                value : Box::into_raw(
                    Box::new(ByteWrapper {
                msg_len : bx.len() as u32,
                msg_ptr : bytes_ptr,
            })
                ) as *mut u8,
            });
            Box::into_raw(res)
        }
        Err(err) => {
            get_error(err)
        },
    }
}

/*

All returned data structures 

 */

/// Given a pointer to the start of a byte array of WAC data
/// encode the data into the codec
/// 
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

use std::any::Any;

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