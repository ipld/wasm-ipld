#[cfg(test)]
mod tests {
    use std::convert::TryInto;

    use wasm_ipld::{decode, load_adl, myalloc, read_adl, seek_adl};

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

    #[test]
    fn test_full_read() {
        let hex_wac_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr = load_adl(wac_file_root.as_mut_ptr(), wac_file_root.len());
            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(40, 0);

            let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!(num_read, 40);
            assert_eq!(buffer.as_slice()[0..30], [0x61; 30]);
            assert_eq!(buffer.as_slice()[30..], [0x62; 10]);
        }
    }

    #[test]
    fn test_partial_reads() {
        let hex_wac_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr = load_adl(wac_file_root.as_mut_ptr(), wac_file_root.len());
            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(20, 0);

            let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!(num_read, 20);
            assert_eq!(buffer.as_slice()[0..20], [0x61; 20]);

            let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!(num_read, 20);
            assert_eq!(buffer.as_slice()[0..10], [0x61; 10]);
            assert_eq!(buffer.as_slice()[10..], [0x62; 10]);
        }
    }

    #[test]
    fn test_seek_read() {
        let hex_wac_file_root = "090406046e616d65060466696c65060c7069656365206c656e677468031e0606706965636573062838666b8ba500faa5c2406f4575d42a92379844c245dfb79d668374f6578b3128746dce59b7a02e8006066c656e6774680328";
        let mut wac_file_root = hex::decode(hex_wac_file_root).unwrap();

        unsafe {
            let adl_ptr = load_adl(wac_file_root.as_mut_ptr(), wac_file_root.len());
            let mut buffer: Vec<u8> = Vec::new();
            buffer.resize(20, 0);

            let seek_to = seek_adl(adl_ptr as *mut u8, 15, 0);
            assert_eq!(seek_to, 15);

            let num_read = read_adl(adl_ptr as *mut u8, buffer.as_mut_ptr(), buffer.len() as i32);
            assert_eq!(num_read, 20);
            assert_eq!(buffer.as_slice()[0..15], [0x61; 15]);
            assert_eq!(buffer.as_slice()[15..], [0x62; 5]);
        }
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
fn main() {}
