use std::convert::TryInto;

use wasm_ipld::{myalloc, decode, load_adl, read_adl};

fn main() {
    // create a `Vec<u8>` as input
    let input = "i50e";
    // call the `alloc` function
    let ptr = myalloc(input.len());
    let mut output : Vec<u8>;
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
    // print the result
    println!("Result: {:#?}", output);

    let hex_cbor_file_root = "A3667069656365735828010101010101010101010101010101010101010102020202020202020202020202020202020202026C7069656365206C656E67746814666C656E6774681828";
    let mut cbor_file_root = hex::decode(hex_cbor_file_root).unwrap();

    unsafe {
        let adl_ptr = load_adl(cbor_file_root.as_mut_ptr(), cbor_file_root.len());
        let mut buffer : Vec<u8> = Vec::new();
        buffer.resize(100, 0);
        
        let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.capacity() as u32);
        println!("Result: read {:#?} bytes", num_read);
        println!("Result: read {:#?} ", buffer.as_slice());
    }
}