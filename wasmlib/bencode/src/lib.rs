use std::{collections::BTreeMap, io::Write};

use example::{get_result_bytes, ValueOrError};
use integer_encoding::VarIntWriter;
use libipld::error::Error;

use wac::WacCode;

// When the `wee_alloc` feature is enabled, use `wee_alloc` as the global
// allocator.
#[cfg(feature = "wee_alloc")]
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

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

    let result: Result<Vec<u8>, libipld::error::Error> = wac_to_bencode_block(data);

    get_result_bytes(result)
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
    let result = bencode_to_wac_block(data);

    get_result_bytes(result)
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

fn bencode_to_wac_block(input: &[u8]) -> Result<Vec<u8>, Error> {
    let mut v = Vec::new();
    decoder_inner(input, 0, &mut v)?;
    Ok(v)
}

fn decoder_inner(
    input: &[u8],
    mut cursor: usize,
    output: &mut Vec<u8>,
) -> Result<(usize, WacCode), Error> {
    match input[cursor] {
        b'i' => {
            cursor += 1;
            let n = input.get(cursor).ok_or_else(|| Error::msg("invalid int"))?;
            match n {
                b'-' => {
                    cursor += 1;
                    let (val, outc) = get_int(input, cursor, b'e')?;
                    output.push(WacCode::NInt as u8);
                    output.write_varint(val)?;
                    cursor = outc;
                    Ok((cursor, WacCode::NInt))
                }
                b'0'..=b'9' => {
                    let (val, outc) = get_int(input, cursor, b'e')?;
                    output.push(WacCode::Int as u8);
                    output.write_varint(val)?;
                    cursor = outc;
                    Ok((cursor, WacCode::Int))
                }
                _ => Err(Error::msg("invalid token")),
            }
        }
        b'l' => {
            cursor += 1;
            output.push(WacCode::List as u8);
            let mut buf = Vec::new();
            let mut num_elems: usize = 0;
            loop {
                if input
                    .get(cursor)
                    .ok_or_else(|| Error::msg("invalid list"))?
                    == &b'e'
                {
                    cursor += 1;
                    output.write_varint(num_elems)?;
                    output.write_all(&buf)?;
                    return Ok((cursor, WacCode::List));
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
                if input.get(cursor).ok_or_else(|| Error::msg("invalid map"))? == &b'e' {
                    cursor += 1;
                    output.write_varint(num_elems)?;
                    output.write_all(&buf)?;
                    return Ok((cursor, WacCode::Map));
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
            output.write_all(&input[cursor..cursor + len])?;
            cursor += len;
            Ok((cursor, WacCode::String))
        }
        _ => Err(Error::msg("invalid token")),
    }
}

fn get_int(input: &[u8], mut cursor: usize, terminator: u8) -> Result<(usize, usize), Error> {
    let mut len_buf = Vec::new();
    loop {
        let n = *input
            .get(cursor)
            .ok_or_else(|| Error::msg("invalid integer"))?;
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

    use example::{myalloc, ByteWrapper, ValueOrError};

    use crate::{decode, encode};

    #[test]
    fn test_int() {
        test_equality("i50e", &[3, 50]);
    }

    #[test]
    fn test_string() {
        test_equality("6:length", &[6, 6, 108, 101, 110, 103, 116, 104])
    }

    #[test]
    fn test_list() {
        test_equality("l4:spami42ee", &[8, 2, 6, 4, 115, 112, 97, 109, 3, 42])
    }

    #[test]
    fn test_map() {
        test_equality(
            "d3:bar4:spam3:fooi42ee",
            &[
                9, 2, 6, 3, 98, 97, 114, 6, 4, 115, 112, 97, 109, 6, 3, 102, 111, 111, 3, 42,
            ],
        )
    }

    #[test]
    fn test_fixture() {
        let block = include_bytes!("../../bittorrent-fixtures/animals-fixtures/animals.infodict");
        let fixture_wac = convert_block(block, decode);
        let hex_fixture_wac = hex::encode(fixture_wac);
        assert_eq!(hex_fixture_wac, "0904060566696c65730802090206066c656e6774680392d510060470617468080106094b6f616c612e6a7067090206066c656e67746803a6dc050604706174680801060970616e64612e6a706706046e616d650607616e696d616c73060c7069656365206c656e677468038080100606706965636573062813da56fd10d288769fdea62d464572c5f16e967ddc462b4d35419ca9230d69d758f0832a30959baa")
    }

    fn test_equality(bencode_block: &str, wac_block: &[u8]) {
        assert_eq!(decode_string(bencode_block), wac_block);
        assert_eq!(encode_bytes(wac_block), bencode_block.as_bytes())
    }

    fn decode_string(input: &str) -> Vec<u8> {
        convert_block(input.as_bytes(), decode)
    }

    fn encode_bytes(input: &[u8]) -> Vec<u8> {
        convert_block(input, encode)
    }

    fn convert_block(
        input: &[u8],
        transform_fn: unsafe fn(ptr: *mut u8, len: u32) -> *const ValueOrError,
    ) -> Vec<u8> {
        // call the `alloc` function
        let ptr = myalloc(input.len());
        let mut output: Vec<u8>;
        unsafe {
            // copy the contents of `input`into the buffer
            // returned by `alloc`
            std::ptr::copy(input.as_ptr(), ptr, input.len());
            // call the `array_sum` function with the pointer
            // and the length of the array
            let res = transform_fn(ptr, input.len() as u32);
            if !(*res).err.is_null() {
                panic!("error in block conversion")
            }
            let val = &*((*res).value as *const ByteWrapper);

            let ol_res = val.msg_len.try_into().unwrap();
            output = vec![0; ol_res];
            std::ptr::copy(val.msg_ptr, output.as_mut_ptr(), ol_res);
        }
        output
    }
}

fn wac_to_bencode_block(input: &[u8]) -> Result<Vec<u8>, Error> {
    let w = wac::from_bytes(input)?;

    let mut v = Vec::new();
    wac_to_bencode_inner(w, &mut v)?;
    Ok(v)
}

fn wac_to_bencode_inner(w: wac::Wac, output: &mut Vec<u8>) -> Result<(), Error> {
    match w {
        wac::Wac::Null => Err(Error::msg("null not supported")),
        wac::Wac::Bool(_) => Err(Error::msg("bool not supported")),
        wac::Wac::Integer(i) => {
            if i >= 0 {
                output.write_all(&[b'i'])?;
                output.write_all(i.to_string().as_bytes())?;
            } else {
                output.write_all(&[b'i', b'-'])?;
                output.write_all((-i).to_string().as_bytes())?;
            }
            output.write_all(&[b'e'])?;
            Ok(())
        }
        wac::Wac::Float(_) => Err(Error::msg("float not supported")),
        wac::Wac::String(s) => {
            output.write_all(s.len().to_string().as_bytes())?;
            output.write_all(&[b':'])?;
            output.write_all(s.as_slice())?;
            Ok(())
        }
        wac::Wac::Bytes(_) => Err(Error::msg("bytes not supported")),
        wac::Wac::List(l) => {
            output.write_all(&[b'l'])?;
            for elem in l {
                wac_to_bencode_inner(elem, output)?;
            }
            output.write_all(&[b'e'])?;
            Ok(())
        }
        wac::Wac::Map(m) => {
            output.write_all(&[b'd'])?;
            // TODO: verify data is ordered correctly
            for (k, v) in m {
                wac_to_bencode_inner(wac::Wac::String(k), output)?;
                wac_to_bencode_inner(v, output)?;
            }
            output.write_all(&[b'e'])?;
            Ok(())
        }
        wac::Wac::Link(_) => Err(Error::msg("link not supported")),
    }
}
