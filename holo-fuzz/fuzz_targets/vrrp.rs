#![no_main]

use holo_vrrp;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    println!("....");
    println!("{:#?}", data);
});
