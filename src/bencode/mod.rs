use std::{collections::BTreeMap, io::Write};

use integer_encoding::VarIntWriter;
use libipld::error::Error;

use crate::wac::WacCode;

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

pub fn decode(input: Vec<u8>) -> Result<Vec<u8>, Error> {
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
