use libc::in_addr;

#[repr(C)]
pub union __vif_union {
    pub vifc_lcl_addr: in_addr,
    pub vifc_lcl_ifindex: std::os::raw::c_int,
}

#[repr(C)]
pub struct vifctl {
    pub vifc_vifi: std::os::raw::c_ushort,
    pub vifc_flags: std::os::raw::c_uchar,
    pub vifc_threshold: std::os::raw::c_uchar,
    pub vifc_rate_limit: std::os::raw::c_uint,
    pub addr_index_union: __vif_union,
    pub vifc_rmt_addr: in_addr,
}
