/* SPDX-License-Identifier: LGPL-2.1-or-later */

use std::ffi::{CStr, c_char, c_int};

//mod pull_varlink;
include!("pull-varlink.rs");

#[unsafe(no_mangle)]
pub extern "C" fn pull_rust(parameters: *const c_char) {
    unsafe { println!("{}", CStr::from_ptr(parameters).to_str().unwrap()); }
}

fn main() {
    println!("Hello, world!");
    unsafe { vl_server(); }
}
