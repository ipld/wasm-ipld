use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::io::{BufRead, Cursor, Write};

use integer_encoding::{VarIntReader, VarIntWriter};
use libipld::{cid::Cid, error::Error};
use num_enum::{IntoPrimitive, TryFromPrimitive};

#[derive(Clone, PartialEq)]
pub enum Wac {
    /// Represents the absence of a value or the value undefined.
    Null,
    /// Represents a boolean value.
    Bool(bool),
    /// Represents an integer.
    Integer(i128),
    /// Represents a floating point value.
    Float(f64),
    /// Represents an UTF-8 string.
    String(Vec<u8>),
    /// Represents a sequence of bytes.
    Bytes(Vec<u8>),
    /// Represents a list.
    List(Vec<Wac>),
    /// Represents a map of strings.
    Map(BTreeMap<Vec<u8>, Wac>),
    /// Represents a map of integers.
    Link(Cid),
}

#[derive(PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum WacCode {
    Null = 0,
    True = 1,
    False = 2,
    Int = 3,
    NInt = 4,
    Float = 5,
    String = 6,
    Bytes = 7,
    List = 8,
    Map = 9,
    Link = 10,
}

pub fn from_bytes(input: &[u8]) -> Result<Wac, Error> {
    let mut cur = Cursor::new(input);
    from_cursor(&mut cur)
}

fn from_cursor(cur: &mut Cursor<&[u8]>) -> Result<Wac, Error> {
    let x = cur
        .get_ref()
        .get(cur.position() as usize)
        .ok_or_else(|| Error::msg("input is empty"))?;
    cur.consume(1);
    let y = WacCode::try_from(*x)?;
    match y {
        WacCode::Null => Ok(Wac::Null),
        WacCode::True => Ok(Wac::Bool(true)),
        WacCode::False => Ok(Wac::Bool(false)),
        WacCode::Int => {
            // TODO: ZigZag issues with varint?
            let i: u64 = cur.read_varint()?;
            Ok(Wac::Integer(i as i128))
        }
        WacCode::NInt => {
            let i: u64 = cur.read_varint()?;
            Ok(Wac::Integer(-(i as i128)))
        }
        WacCode::Float => todo!(),
        WacCode::String => {
            let len: u64 = cur.read_varint()?;
            let len = len as usize;
            let mut buf: Vec<u8> = Vec::new();
            let cp = cur.position() as usize;
            buf.extend_from_slice(&(cur.get_ref()[cp..cp + len]));
            cur.consume(len);
            Ok(Wac::String(buf))
        }
        WacCode::Bytes => {
            let len: u64 = cur.read_varint()?;
            let len = len as usize;
            let mut buf: Vec<u8> = Vec::new();
            let cp = cur.position() as usize;
            buf.extend_from_slice(&(cur.get_ref()[cp..cp + len]));
            cur.consume(len);
            Ok(Wac::Bytes(buf))
        }
        WacCode::List => {
            let mut v = Vec::new();
            let len: u64 = cur.read_varint()?;
            for _ in 0..len {
                let elem = from_cursor(cur)?;
                v.push(elem);
            }
            Ok(Wac::List(v))
        }
        WacCode::Map => {
            let mut v = BTreeMap::new();
            let len: u64 = cur.read_varint()?;
            for _ in 0..len {
                let key = from_cursor(cur)?;
                match key {
                    Wac::String(s) => {
                        let val = from_cursor(cur)?;
                        v.insert(s, val);
                    }
                    _ => return Err(Error::msg("only string map keys are supported")),
                }
            }
            Ok(Wac::Map(v))
        }
        WacCode::Link => {
            let c = Cid::read_bytes(cur)?;
            Ok(Wac::Link(c))
        }
    }
}

pub fn into_bytes(input: Wac) -> Result<Vec<u8>, Error> {
    let mut out: Vec<u8> = Vec::new();
    into_bytes_inner(input, &mut out)?;
    Ok(out)
}

fn into_bytes_inner(input: Wac, output: &mut Vec<u8>) -> Result<(), Error> {
    match input {
        Wac::Null => {
            output.push(WacCode::Null.into());
            Ok(())
        }
        Wac::Bool(b) => {
            if b {
                output.push(WacCode::True.into());
            } else {
                output.push(WacCode::False.into());
            }
            Ok(())
        }
        Wac::Integer(i) => {
            if i > 0 {
                output.push(WacCode::Int.into());
                output.write_varint(i as i64)?;
                Ok(())
            } else {
                output.push(WacCode::NInt.into());
                output.write_varint((-i) as i64)?;
                Ok(())
            }
        }
        Wac::Float(_) => todo!(),
        Wac::String(s) => {
            output.push(WacCode::String.into());
            output.write_varint(s.len())?;
            output.write_all(&s)?;
            Ok(())
        }
        Wac::Bytes(b) => {
            output.push(WacCode::Bytes.into());
            output.write_varint(b.len())?;
            output.write_all(&b)?;
            Ok(())
        }
        Wac::List(l) => {
            output.push(WacCode::List.into());
            output.write_varint(l.len())?;
            for elem in l {
                into_bytes_inner(elem, output)?;
            }
            Ok(())
        }
        Wac::Map(m) => {
            output.push(WacCode::Map.into());
            output.write_varint(m.len())?;

            for (k, v) in m {
                into_bytes_inner(Wac::Bytes(k), output)?;
                into_bytes_inner(v, output)?;
            }
            Ok(())
        }
        Wac::Link(c) => {
            output.push(WacCode::Link.into());
            c.write_bytes(output)?;
            Ok(())
        }
    }
}
