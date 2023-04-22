use std::{io::{self, BufReader, BufRead}, fs::File, ops::{Range, Add, AddAssign}, collections::BTreeSet, iter::Sum};

/// Helper to load and manage application-defined kernel symbols
#[derive(Default)]
pub struct KSyms {
    net_rx_action: Range<u64>,
    __napi_poll: Range<u64>,
    netif_receive_skb: Range<u64>,
    netif_receive_skb_core: Range<u64>,
    netif_receive_skb_list_internal: Range<u64>,
    napi_gro_receive: Range<u64>,
    do_xdp_generic: Range<u64>,
    tcf_classify: Range<u64>,
    br_handle_frame: Range<u64>,
    ip_forward: Range<u64>,
    ip6_forward: Range<u64>,
    ip_local_deliver: Range<u64>,
    ip6_input: Range<u64>
}

/// Counts instances of symbols in stack traces
#[derive(Default, Clone, Copy)]
pub struct Counts {
    pub net_rx_action: usize,
    pub __napi_poll: usize,
    /// Catch-all for any function to submit frames to the network stack
    pub netif_receive_skb: usize,
    pub br_handle_frame: usize,
    /// netif_receive_skb when called by br_handle_frame
    pub netif_receive_skb_sub_br: usize,
    pub do_xdp_generic: usize,
    pub tcf_classify: usize,
    pub ip_forward: usize,
    pub ip6_forward: usize,
    pub ip_local_deliver: usize,
    pub ip6_input: usize
}

impl KSyms {
    fn empty() -> Self {
        Default::default()
    }

    fn find_range_end(range: &mut Range<u64>, addrs: &BTreeSet<u64>) {
        // TODO: remove me!
        // Checks if the symbol was found
        assert_ne!(range.start, 0);
        
        range.end = addrs
            .range(range.start+1..)
            .next()
            .cloned()
            .unwrap_or(range.start + 1);
    }
    
    /// Load requested kernel symbols from /proc/kallsyms
    pub fn load() -> io::Result<Self> {
        let mut syms = Self::empty();
        let mut btree = BTreeSet::new();
        let f = BufReader::new(File::open("/proc/kallsyms")?);
        
        // Load all the addresses into a BTreeMap
        for line in f.lines() {
            let line = line?;
            let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
            let name = parts[2];
            let addr = u64::from_str_radix(parts[0], 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, line.clone()))?;

            btree.insert(addr);

            match name {
                "net_rx_action"                   => &mut syms.net_rx_action,
                "__napi_poll"                     => &mut syms.__napi_poll,
                "netif_receive_skb"               => &mut syms.netif_receive_skb,
                "netif_receive_skb_core"          => &mut syms.netif_receive_skb_core,
                "netif_receive_skb_list_internal" => &mut syms.netif_receive_skb_list_internal,
                "napi_gro_receive"                => &mut syms.napi_gro_receive,
                "do_xdp_generic"                  => &mut syms.do_xdp_generic,
                "tcf_classify"                    => &mut syms.tcf_classify,
                "br_handle_frame"                 => &mut syms.br_handle_frame,
                "ip_forward"                      => &mut syms.ip_forward,
                "ip6_forward"                     => &mut syms.ip6_forward,
                "ip_local_deliver"                => &mut syms.ip_local_deliver,
                "ip6_input"                       => &mut syms.ip6_input,

                _ => continue
            }.start = addr;
        }

        // Find range endings
        Self::find_range_end(&mut syms.net_rx_action, &btree);
        Self::find_range_end(&mut syms.__napi_poll, &btree);
        Self::find_range_end(&mut syms.netif_receive_skb, &btree);
        Self::find_range_end(&mut syms.netif_receive_skb_core, &btree);
        Self::find_range_end(&mut syms.netif_receive_skb_list_internal, &btree);
        Self::find_range_end(&mut syms.napi_gro_receive, &btree);
        Self::find_range_end(&mut syms.do_xdp_generic, &btree);
        Self::find_range_end(&mut syms.tcf_classify, &btree);
        Self::find_range_end(&mut syms.br_handle_frame, &btree);
        Self::find_range_end(&mut syms.ip_forward, &btree);
        Self::find_range_end(&mut syms.ip6_forward, &btree);
        Self::find_range_end(&mut syms.ip_local_deliver, &btree);
        Self::find_range_end(&mut syms.ip6_input, &btree);

        Ok(syms)
    }
}

impl Counts {
    /// Iterate over the frames in the trace and accumulate the instances of the symbols in this Counts
    #[inline]
    pub unsafe fn acc_trace(&mut self, ksyms: &KSyms, trace_ptr: *const u64, max_frames: usize) {
        let mut c = Self::default();
        
        for frame_idx in 0..max_frames {
            // Load stack frame
            let ip = trace_ptr.add(frame_idx).read_volatile();
            if ip == 0 {
                break;
            }

            // Check for known symbols
            let cnt = match ip {
                _ if ksyms.net_rx_action.contains(&ip) => &mut c.net_rx_action,
                _ if ksyms.__napi_poll.contains(&ip) => &mut c.__napi_poll,
                _ if [&ksyms.netif_receive_skb, &ksyms.netif_receive_skb_core, &ksyms.netif_receive_skb_list_internal, &ksyms.napi_gro_receive]
                    .iter().any(|r| r.contains(&ip)) => &mut c.netif_receive_skb,
                _ if ksyms.do_xdp_generic.contains(&ip) => &mut c.do_xdp_generic,
                _ if ksyms.tcf_classify.contains(&ip) => &mut c.tcf_classify,
                _ if ksyms.br_handle_frame.contains(&ip) => {
                    c.netif_receive_skb_sub_br = std::mem::take(&mut c.netif_receive_skb);
                    &mut c.br_handle_frame
                },
                _ if ksyms.ip_forward.contains(&ip) => &mut c.ip_forward,
                _ if ksyms.ip6_forward.contains(&ip) => &mut c.ip6_forward,
                _ if ksyms.ip_local_deliver.contains(&ip) => &mut c.ip_local_deliver,
                _ if ksyms.ip6_input.contains(&ip) => &mut c.ip6_input,
                
                _ => continue
            };

            *cnt = 1;
        }

        // DEBUG: output stack trace
        // if c.ip_local_deliver != 0 {
        //     use std::io::Write;
        //     let mut f = File::create("stack_trace").unwrap();
        //     for frame_idx in 0..max_frames {
        //         let ip = trace_ptr.add(frame_idx).read_volatile();
        //         if ip == 0 {
        //             break;
        //         }
        //         writeln!(&mut f, "{ip}").unwrap();
        //     }
        // }

        *self += c;
    }
}

impl Add for Counts {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            net_rx_action:            self.net_rx_action            + rhs.net_rx_action,
            __napi_poll:              self.__napi_poll              + rhs.__napi_poll,
            netif_receive_skb:        self.netif_receive_skb        + rhs.netif_receive_skb,
            do_xdp_generic:           self.do_xdp_generic           + rhs.do_xdp_generic,
            tcf_classify:             self.tcf_classify             + rhs.tcf_classify,
            br_handle_frame:          self.br_handle_frame          + rhs.br_handle_frame,
            netif_receive_skb_sub_br: self.netif_receive_skb_sub_br + rhs.netif_receive_skb_sub_br,
            ip_forward:               self.ip_forward               + rhs.ip_forward,
            ip6_forward:              self.ip6_forward              + rhs.ip6_forward,
            ip_local_deliver:         self.ip_local_deliver         + rhs.ip_local_deliver,
            ip6_input:                self.ip6_input                + rhs.ip6_input
        }
    }
}

impl AddAssign for Counts {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl Sum for Counts {
    fn sum<I: Iterator<Item = Self>>(iter: I) -> Self {
        iter.reduce(|acc, e| acc + e).unwrap_or_default()
    }
}
