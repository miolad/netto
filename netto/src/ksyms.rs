use std::{io::{self, BufReader, BufRead}, fs::File, ops::{Add, AddAssign}, collections::BTreeMap, iter::Sum};
#[cfg(feature = "save-traces")]
use std::io::Write;

/// Helper to load and manage application-defined kernel symbols
#[derive(Default)]
pub struct KSyms {
    syms: BTreeMap<u64, KSymsVal>
}

type SymbolFun = Box<dyn for<'a> Fn(&'a mut Counts, &'a mut PerFrameProps) -> Option<&'a mut u16>>;

struct KSymsVal {
    range_end: u64,
    fun: SymbolFun
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
    pub napi_gro_receive_overhead: u16,
    pub nf_conntrack_in: u16,
    // pub nf_local_in_v4: u16,
    // pub nf_local_in_v6: u16,
    // pub nf_forward_v4: u16,
    // pub nf_forward_v6: u16
}

struct PerFrameProps {
    in_nf_hook: u16,
    ip_rcv_finish: u16
}

impl KSyms {
    /// Load requested kernel symbols from /proc/kallsyms
    pub fn load() -> io::Result<Self> {
        let mut btree = BTreeMap::new();
        let f = BufReader::new(File::open("/proc/kallsyms")?);
        
        // Load all the addresses into a BTreeMap
        for line in f.lines() {
            let line = line?;
            let parts = line.split_ascii_whitespace().collect::<Vec<_>>();
            let name = parts[2];
            let addr = u64::from_str_radix(parts[0], 16)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, line.clone()))?;

            btree.insert(addr, name.to_string());
        }

        // Only keep the symbols we're interested in
        let syms = btree
            .iter()
            .filter_map(|(&range_start, name)| {
                match name.as_str() {
                    "net_rx_action" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, _| Some(&mut cnt.net_rx_action)
                    )),
                    "__napi_poll" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, _| Some(&mut cnt.__napi_poll)
                    )),
                    "netif_receive_skb" | "netif_receive_skb_core" | "netif_receive_skb_list_internal" | "__netif_receive_skb" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            cnt.nf_netdev_ingress = cnt.nf_netdev_ingress.max(std::mem::take(in_nf_hook));
                            Some(&mut cnt.netif_receive_skb)
                        }
                    )),
                    "napi_gro_receive" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            cnt.nf_netdev_ingress = cnt.nf_netdev_ingress.max(std::mem::take(in_nf_hook));

                            if cnt.netif_receive_skb == 0 {
                                cnt.napi_gro_receive_overhead = 1;
                            }
                            
                            Some(&mut cnt.netif_receive_skb)
                        }
                    )),
                    "do_xdp_generic" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, _| Some(&mut cnt.do_xdp_generic)
                    )),
                    "tcf_classify" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, _| Some(&mut cnt.tcf_classify)
                    )),
                    "br_handle_frame" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            *in_nf_hook = 0;
                            cnt.netif_receive_skb_sub_br = std::mem::take(&mut cnt.netif_receive_skb);
                            Some(&mut cnt.br_handle_frame)
                        }
                    )),
                    "ip_forward" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            *in_nf_hook = 0;
                            Some(&mut cnt.ip_forward)
                        }
                    )),
                    "ip6_forward" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            *in_nf_hook = 0;
                            Some(&mut cnt.ip6_forward)
                        }
                    )),
                    "ip_local_deliver" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            *in_nf_hook = 0;
                            Some(&mut cnt.ip_local_deliver)
                        }
                    )),
                    "ip6_input" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, .. }| {
                            *in_nf_hook = 0;
                            Some(&mut cnt.ip6_input)
                        }
                    )),
                    "nf_hook_slow" => Option::<SymbolFun>::Some(Box::new(
                        |_, PerFrameProps { in_nf_hook, .. }| Some(in_nf_hook)
                    )),
                    "ip_rcv" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, ip_rcv_finish, .. }| {
                            if *ip_rcv_finish == 0 {
                                cnt.nf_prerouting_v4 = cnt.nf_prerouting_v4.max(*in_nf_hook);
                            }
                            *in_nf_hook = 0;
                            None
                        }
                    )),
                    "ip6_rcv" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, PerFrameProps { in_nf_hook, ip_rcv_finish, ..}| {
                            if *ip_rcv_finish == 0 {
                                cnt.nf_prerouting_v6 = cnt.nf_prerouting_v6.max(*in_nf_hook);
                            }
                            *in_nf_hook = 0;
                            None
                        }
                    )),
                    "ip_rcv_finish" | "ip6_rcv_finish" => Option::<SymbolFun>::Some(Box::new(
                        |_, PerFrameProps { ip_rcv_finish, .. }| Some(ip_rcv_finish)
                    )),
                    "nf_conntrack_in" => Option::<SymbolFun>::Some(Box::new(
                        |cnt, _| Some(&mut cnt.nf_conntrack_in)
                    )),

                    _ => None
                }.map(|fun| (range_start, KSymsVal {
                    range_end: btree
                        .range(range_start+1..)
                        .next()
                        .map(|(&addr, _)| addr)
                        .unwrap_or(range_start + 1),
                    fun
                }))
            })
            .collect();

        Ok(Self { syms })
    }
}

impl Counts {
    /// Iterate over the frames in the trace and accumulate the instances of the symbols in this Counts
    #[inline]
    pub unsafe fn acc_trace(
        &mut self,
        ksyms: &KSyms,
        trace_ptr: *const u64,
        max_frames: usize,
        #[cfg(feature = "save-traces")]
        mut output: impl Write
    ) {
        #[cfg(feature = "save-traces")]
        let mut first_iter = true;
        
        let mut c = Self::default();
        let mut frame_props = PerFrameProps {
            in_nf_hook: 0,
            ip_rcv_finish: 0
        };

        for frame_idx in 0..max_frames {
            // Load stack frame
            let ip = trace_ptr.add(frame_idx).read_volatile();
            if ip == 0 {
                break;
            }

            #[cfg(feature = "save-traces")]
            {
                let _ = write!(output, "{}{ip}", if first_iter { "" } else { "," });
                first_iter = false;
            }

            // Check for known symbols
            if let Some((_, KSymsVal { range_end, fun })) = ksyms
                .syms
                .range(..=ip)
                .next_back() {
                    if ip < *range_end {
                        if let Some(cnt) = fun(&mut c, &mut frame_props) {
                            *cnt = 1;
                        }
                    }
                }
        }

        #[cfg(feature = "save-traces")]
        let _ = writeln!(output);

        *self += c;
    }
}

impl Add for Counts {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self {
            net_rx_action:             self.net_rx_action             + rhs.net_rx_action,
            __napi_poll:               self.__napi_poll               + rhs.__napi_poll,
            netif_receive_skb:         self.netif_receive_skb         + rhs.netif_receive_skb,
            do_xdp_generic:            self.do_xdp_generic            + rhs.do_xdp_generic,
            tcf_classify:              self.tcf_classify              + rhs.tcf_classify,
            br_handle_frame:           self.br_handle_frame           + rhs.br_handle_frame,
            netif_receive_skb_sub_br:  self.netif_receive_skb_sub_br  + rhs.netif_receive_skb_sub_br,
            ip_forward:                self.ip_forward                + rhs.ip_forward,
            ip6_forward:               self.ip6_forward               + rhs.ip6_forward,
            ip_local_deliver:          self.ip_local_deliver          + rhs.ip_local_deliver,
            ip6_input:                 self.ip6_input                 + rhs.ip6_input,
            nf_netdev_ingress:         self.nf_netdev_ingress         + rhs.nf_netdev_ingress,
            nf_prerouting_v4:          self.nf_prerouting_v4          + rhs.nf_prerouting_v4,
            nf_prerouting_v6:          self.nf_prerouting_v6          + rhs.nf_prerouting_v6,
            napi_gro_receive_overhead: self.napi_gro_receive_overhead + rhs.napi_gro_receive_overhead,
            nf_conntrack_in:           self.nf_conntrack_in           + rhs.nf_conntrack_in
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
