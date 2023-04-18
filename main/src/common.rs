/* automatically generated by rust-bindgen 0.64.0 */

pub type __u64 = ::std::os::raw::c_ulonglong;
pub type u64_ = __u64;
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct per_event_data {
    pub prev_ts: u64_,
    pub total_time: u64_,
}
#[test]
fn bindgen_test_layout_per_event_data() {
    const UNINIT: ::std::mem::MaybeUninit<per_event_data> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<per_event_data>(),
        16usize,
        concat!("Size of: ", stringify!(per_event_data))
    );
    assert_eq!(
        ::std::mem::align_of::<per_event_data>(),
        8usize,
        concat!("Alignment of ", stringify!(per_event_data))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).prev_ts) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(per_event_data),
            "::",
            stringify!(prev_ts)
        )
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).total_time) as usize - ptr as usize },
        8usize,
        concat!(
            "Offset of field: ",
            stringify!(per_event_data),
            "::",
            stringify!(total_time)
        )
    );
}
#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct per_cpu_data {
    #[doc = " @brief One for each possible event"]
    pub events: [per_event_data; 9usize],
}
#[test]
fn bindgen_test_layout_per_cpu_data() {
    const UNINIT: ::std::mem::MaybeUninit<per_cpu_data> = ::std::mem::MaybeUninit::uninit();
    let ptr = UNINIT.as_ptr();
    assert_eq!(
        ::std::mem::size_of::<per_cpu_data>(),
        144usize,
        concat!("Size of: ", stringify!(per_cpu_data))
    );
    assert_eq!(
        ::std::mem::align_of::<per_cpu_data>(),
        8usize,
        concat!("Alignment of ", stringify!(per_cpu_data))
    );
    assert_eq!(
        unsafe { ::std::ptr::addr_of!((*ptr).events) as usize - ptr as usize },
        0usize,
        concat!(
            "Offset of field: ",
            stringify!(per_cpu_data),
            "::",
            stringify!(events)
        )
    );
}
