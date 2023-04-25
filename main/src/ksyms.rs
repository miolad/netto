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
    ip6_input: Range<u64>,
    ip_rcv: Range<u64>,
    ipv6_rcv: Range<u64>,
    ip_rcv_finish: Range<u64>,
    ip6_rcv_finish: Range<u64>,
    nf_hook_slow: Range<u64>
}

/// Counts instances of symbols in stack traces
#[derive(Default, Clone, Copy)]
pub struct Counts {
    pub net_rx_action: u16,
    pub __napi_poll: u16,
    /// Catch-all for any function to submit frames to the network stack
    pub netif_receive_skb: u16,
    pub br_handle_frame: u16,
    /// netif_receive_skb when called by br_handle_frame
    pub netif_receive_skb_sub_br: u16,
    pub do_xdp_generic: u16,
    pub tcf_classify: u16,
    pub ip_forward: u16,
    pub ip6_forward: u16,
    pub ip_local_deliver: u16,
    pub ip6_input: u16,
    pub nf_netdev_ingress: u16,
    pub nf_prerouting_v4: u16,
    pub nf_prerouting_v6: u16,
    // pub nf_local_in_v4: u16,
    // pub nf_local_in_v6: u16,
    // pub nf_forward_v4: u16,
    // pub nf_forward_v6: u16
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
                "ip_rcv"                          => &mut syms.ip_rcv,
                "ipv6_rcv"                        => &mut syms.ipv6_rcv,
                "ip_rcv_finish"                   => &mut syms.ip_rcv_finish,
                "ip6_rcv_finish"                  => &mut syms.ip6_rcv_finish,
                "nf_hook_slow"                    => &mut syms.nf_hook_slow,

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
        Self::find_range_end(&mut syms.ip_rcv, &btree);
        Self::find_range_end(&mut syms.ipv6_rcv, &btree);
        Self::find_range_end(&mut syms.ip_rcv_finish, &btree);
        Self::find_range_end(&mut syms.ip6_rcv_finish, &btree);
        Self::find_range_end(&mut syms.nf_hook_slow, &btree);

        Ok(syms)
    }
}

impl Counts {
    /// Iterate over the frames in the trace and accumulate the instances of the symbols in this Counts
    #[inline]
    pub unsafe fn acc_trace(&mut self, ksyms: &KSyms, trace_ptr: *const u64, max_frames: usize) {
        let mut c = Self::default();
        let mut in_nf_hook = 0;
        let mut ip_rcv_finish = 0;
        
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
                    .iter().any(|r| r.contains(&ip)) => {
                        c.nf_netdev_ingress = c.nf_netdev_ingress.max(std::mem::take(&mut in_nf_hook));
                        &mut c.netif_receive_skb
                    },
                _ if ksyms.do_xdp_generic.contains(&ip) => &mut c.do_xdp_generic,
                _ if ksyms.tcf_classify.contains(&ip) => &mut c.tcf_classify,
                _ if ksyms.br_handle_frame.contains(&ip) => {
                    in_nf_hook = 0;
                    c.netif_receive_skb_sub_br = std::mem::take(&mut c.netif_receive_skb);
                    &mut c.br_handle_frame
                },
                _ if ksyms.ip_forward.contains(&ip) => {
                    in_nf_hook = 0;
                    // c.nf_forward_v4 = c.nf_forward_v4.max(std::mem::take(&mut in_nf_hook));
                    &mut c.ip_forward
                },
                _ if ksyms.ip6_forward.contains(&ip) => {
                    in_nf_hook = 0;
                    // c.nf_forward_v6 = c.nf_forward_v6.max(std::mem::take(&mut in_nf_hook));
                    &mut c.ip6_forward
                },
                _ if ksyms.ip_local_deliver.contains(&ip) => {
                    in_nf_hook = 0;
                    // c.nf_local_in_v4 = c.nf_local_in_v4.max(std::mem::take(&mut in_nf_hook));
                    &mut c.ip_local_deliver
                },
                _ if ksyms.ip6_input.contains(&ip) => {
                    in_nf_hook = 0;
                    // c.nf_local_in_v6 = c.nf_local_in_v6.max(std::mem::take(&mut in_nf_hook));
                    &mut c.ip6_input
                },
                _ if ksyms.nf_hook_slow.contains(&ip) => &mut in_nf_hook,
                _ if ksyms.ip_rcv.contains(&ip) => {
                    if ip_rcv_finish == 0 {
                        c.nf_prerouting_v4 = c.nf_prerouting_v4.max(in_nf_hook);
                    }
                    in_nf_hook = 0;
                    continue;
                }
                _ if ksyms.ipv6_rcv.contains(&ip) => {
                    if ip_rcv_finish == 0 {
                        c.nf_prerouting_v6 = c.nf_prerouting_v6.max(in_nf_hook);
                    }
                    in_nf_hook = 0;
                    continue;
                }
                _ if ksyms.ip_rcv_finish.contains(&ip) || ksyms.ip6_rcv_finish.contains(&ip) => {
                    &mut ip_rcv_finish
                }
                
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
            ip6_input:                self.ip6_input                + rhs.ip6_input,
            nf_netdev_ingress:        self.nf_netdev_ingress        + rhs.nf_netdev_ingress,
            nf_prerouting_v4:         self.nf_prerouting_v4         + rhs.nf_prerouting_v4,
            nf_prerouting_v6:         self.nf_prerouting_v6         + rhs.nf_prerouting_v6,
            // nf_local_in_v4:           self.nf_local_in_v4           + rhs.nf_local_in_v4,
            // nf_local_in_v6:           self.nf_local_in_v6           + rhs.nf_local_in_v6,
            // nf_forward_v4:            self.nf_forward_v4            + rhs.nf_forward_v4,
            // nf_forward_v6:            self.nf_forward_v6            + rhs.nf_forward_v6
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
