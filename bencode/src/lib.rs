use std::{collections::BTreeMap, io::Write};

use integer_encoding::VarIntWriter;
use libipld::error::Error;

use wac::WacCode;

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

/// Given a pointer to the start of a byte array and
/// its length, decode it into a standard IPLD codec representation
/// (for now WAC)
#[no_mangle]
pub unsafe fn decode(ptr: *mut u8, len: usize, out_len: &mut u32) -> *const u8 {
    let data = Vec::from_raw_parts(ptr, len, len);
    let result = decode_block(data, out_len);

    let bx = result.into_boxed_slice();
    Box::into_raw(bx) as *const u8
}

fn decode_block(input: Vec<u8>, out_len: &mut u32) -> Vec<u8> {
    let res = bencode_to_wac_block(input);
    match res {
        Ok(v) => {
            *out_len = v.len() as u32;
            return v;
        }
        Err(x) => panic!("{:#?}", x),
    }
}

pub enum WacBencode {
    /// Represents an integer.
    Integer(i128),
    /// Represents a sequence of bytes.
    Bytes(Vec<u8>),
    /// Represents a list.
    List(Vec<WacBencode>),
    /// Represents a map of strings.
    Map(BTreeMap<Vec<u8>, WacBencode>),
}

pub fn bencode_to_wac_block(input: Vec<u8>) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    decoder_inner(&input, 0, &mut v)?;
    Ok(v)
}

fn decoder_inner(
    input: &Vec<u8>,
    mut cursor: usize,
    output: &mut Vec<u8>,
) -> Result<(usize, WacCode), Error> {
    match input[cursor] {
        b'i' => {
            cursor += 1;
            let n = input.get(cursor).ok_or(Error::msg("invalid int"))?;
            match n {
                b'-' => {
                    cursor += 1;
                    let (val, outc) = get_int(input, cursor, b'e')?;
                    output.push(WacCode::NInt as u8);
                    output.write_varint(val)?;
                    cursor = outc;
                    return Ok((cursor, WacCode::NInt));
                }
                b'0'..=b'9' => {
                    let (val, outc) = get_int(input, cursor, b'e')?;
                    output.push(WacCode::Int as u8);
                    output.write_varint(val)?;
                    cursor = outc;
                    return Ok((cursor, WacCode::Int));
                }
                _ => return Err(Error::msg("invalid token")),
            }
        }
        b'l' => {
            cursor += 1;
            output.push(WacCode::List as u8);
            let mut buf = Vec::new();
            let mut num_elems: usize = 0;
            loop {
                match input.get(cursor).ok_or(Error::msg("invalid list"))? {
                    b'e' => {
                        output.write_varint(num_elems)?;
                        output.write(&buf)?;
                        return Ok((cursor, WacCode::List));
                    }
                    _ => (),
                }
                let (outc, _) = decoder_inner(input, cursor, &mut buf)?;
                num_elems += 1;
                cursor = outc;
            }
        }
        b'd' => {
            cursor += 1;
            output.push(WacCode::Map as u8);

            let mut buf = Vec::new();
            let mut num_elems: usize = 0;
            loop {
                match input.get(cursor).ok_or(Error::msg("invalid map"))? {
                    b'e' => {
                        output.write_varint(num_elems)?;
                        output.write(&buf)?;
                        return Ok((cursor, WacCode::Map));
                    }
                    _ => (),
                }

                // keys must be bytestrings
                let (outc, key_type) = decoder_inner(input, cursor, &mut buf)?;
                if key_type != WacCode::String {
                    return Err(Error::msg("map keys must be strings"));
                }
                cursor = outc;
                let (outc, _) = decoder_inner(input, cursor, &mut buf)?;
                num_elems += 1;
                cursor = outc;
            }
        }
        b'0'..=b'9' => {
            let (len, outc) = get_int(input, cursor, b':')?;
            cursor = outc;
            output.push(WacCode::String as u8);
            output.write_varint(len)?;
            output.write(&input[cursor..cursor + len])?;
            cursor += len;
            return Ok((cursor, WacCode::String));
        }
        _ => return Err(Error::msg("invalid token")),
    }
}

fn get_int(input: &Vec<u8>, mut cursor: usize, terminator: u8) -> Result<(usize, usize), Error> {
    let mut len_buf = Vec::new();
    loop {
        let n = *input.get(cursor).ok_or(Error::msg("invalid integer"))?;
        match n {
            end if end == terminator => {
                // TODO: leading zeros check
                let len = String::from_utf8(len_buf.clone())?.parse()?;
                cursor += 1;
                return Ok((len, cursor));
            }
            n @ b'0'..=b'9' => len_buf.push(n),
            _ => return Err(Error::msg("invalid integer")),
        }
        cursor += 1
    }
}

#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use crate::{decode, myalloc};

    #[test]
    fn test_int() {
        assert_eq!(decode_string("i50e"), [3, 50])
    }

    #[test]
    fn test_string() {
        assert_eq!(
            decode_string("6:length"),
            [6, 6, 108, 101, 110, 103, 116, 104]
        )
    }

    #[test]
    fn test_list() {
        assert_eq!(
            decode_string("l4:spami42ee"),
            [8, 2, 6, 4, 115, 112, 97, 109, 3, 42]
        )
    }

    #[test]
    fn test_map() {
        assert_eq!(
            decode_string("d3:bar4:spam3:fooi42ee"),
            [9, 2, 6, 3, 98, 97, 114, 6, 4, 115, 112, 97, 109, 6, 3, 102, 111, 111, 3, 42,]
        )
    }

    fn decode_string(input: &str) -> Vec<u8> {
        // call the `alloc` function
        let ptr = myalloc(input.len());
        let mut output: Vec<u8>;
        unsafe {
            // copy the contents of `input`into the buffer
            // returned by `alloc`
            std::ptr::copy(input.as_ptr(), ptr, input.len());
            // call the `array_sum` function with the pointer
            // and the length of the array
            let mut output_len: u32 = 0;
            let res_start = decode(ptr, input.len(), &mut output_len);

            let ol_res = output_len.try_into().unwrap();
            output = vec![0; ol_res];
            std::ptr::copy(res_start, output.as_mut_ptr(), ol_res);
        }
        println!("{:#?}", output);

        return output;
    }
}
