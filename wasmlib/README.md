# Getting Started

## Building a new Codec/ADLs

1. Create your package
   - Optionally do things like set the global allocator
2. Bring in the relevant traits from the helpers package and implement it for some your struct
3. Copy paste from the helpers package the FFI exports that match the name and signature of the functions in your traits, but are missing `self` and are prefaced by `no_mangle`
4. For each exported function return `MyStruct{}.function(params,...)` 
5. Build with `cargo build --target wasm32-unknown-unknown --release`
6. Use your WASM module 🎉, for example by testing with the gobind package

## Recommendations

Some advice from a new, and likely uninformed, Rustacean (send PRs with better suggestions!):
1. If you create some enum like `ReturnedValues` to track all returned values in your ADL it'll make it easier for you to return errors rather than having undefined behavior if the caller passes in the wrong pointer type by accident
2. Do as little as you can in the unsafe functions and move to safe functions that return errors. You can then process those errors and return them across the FFI boundary