use std::convert::TryInto;

use wasm_ipld::{myalloc, decode, load_adl, read_adl};

fn main() {
    testFoo("i50e");
    testFoo("6:length");
    testFoo("l4:spami42ee");
    testFoo("d3:bar4:spam3:fooi42ee");

    // note: 09 means wac
    let hex_cbor_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
    //let hex_cbor_file_root = "090406066c656e6774680392d51006046e616d6506094b6f616c612e6a7067060c7069656365206c656e677468038080100606706965636573062813da56fd10d288769fdea62d464572c5f16e967d4f02d20480f315ab16f71bf834a968e65baf90c5";
    //let hex_cbor_file_root = "a4646e616d65694b6f616c612e6a7067666c656e6774681a00042a9266706965636573782813da56fd10d288769fdea62d464572c5f16e967d4f02d20480f315ab16f71bf834a968e65baf90c56c7069656365206c656e6774681a00040000";
    //let hex_cbor_file_root = "A3667069656365735828010101010101010101010101010101010101010102020202020202020202020202020202020202026C7069656365206C656E67746814666C656E6774681828";
    let mut cbor_file_root = hex::decode(hex_cbor_file_root).unwrap();

    unsafe {
        let adl_ptr = load_adl(cbor_file_root.as_mut_ptr(), cbor_file_root.len());
        let mut buffer : Vec<u8> = Vec::new();
        buffer.resize(40, 0);
        
        let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
        println!("Result: read {:#?} bytes", num_read);
        println!("Result: read {:#?} ", buffer.as_slice());

        let adl_ptr = load_adl(cbor_file_root.as_mut_ptr(), cbor_file_root.len());
        let mut buffer : Vec<u8> = Vec::new();
        buffer.resize(20, 0);

        let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
        println!("Result: read {:#?} bytes", num_read);
        println!("Result: read {:#?} ", buffer.as_slice());

        let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
        println!("Result: read {:#?} bytes", num_read);
        println!("Result: read {:#?} ", buffer.as_slice());
    }
}

fn testFoo(input : &str) {
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
}