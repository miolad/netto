use std::collections::HashMap;
use cursive::{CursiveRunnable, views::{TextContent, LinearLayout, TextView, DummyView, PaddedView, ScrollView}, theme::Color, view::Resizable, event::{Event, Key}};

/// Manager for the Terminal User Interface for displaying performance data
pub struct Tui {
    /// Interface into the textual contents of all the cells of the table.
    /// 
    /// The external list has one entry for each CPU, and the inner HashMap
    /// maps the metric name with the TextContent component linked with the
    /// corresponding TextView.
    /// 
    /// The map at index num_possible_cpus refers to the cumulative column
    text_contents: Vec<HashMap<&'static str, TextContent>>,

    /// TextContent for the total networking power
    power_content: TextContent
}

impl Tui {
    /// Initialize the tui
    pub fn init(num_cpus: usize) -> (CursiveRunnable, Self) {
        let mut siv = cursive::default();

        // Set a global callback to exit the application
        siv.set_global_callback('q', |c| c.quit());
        siv.set_global_callback(Event::Key(Key::Esc), |c| c.quit());

        let mut text_contents = Vec::with_capacity(num_cpus + 1);
        let black = Color::Rgb(0, 0, 0);
        let description_col = LinearLayout::vertical()
            .child(
                TextView::new("metrics\\cpus")
                    .center()
                    .style(black)
            )
            .child(DummyView)
            .child(TextView::new("TX syscalls").style(black))
            .child(TextView::new("TX softirq").style(black))
            .child(TextView::new("RX softirq").style(black))
            .child(TextView::new(" \u{251c} driver poll").style(black))
            .child(TextView::new(" \u{251c} XDP generic").style(black))
            .child(TextView::new(" \u{251c} TC classify").style(black))
            .child(TextView::new(" \u{251c} NF ingress").style(black))
            .child(TextView::new(" \u{251c} bridging").style(black))
            .child(TextView::new(" \u{251c} NF prerouting").style(black))
            .child(TextView::new(" \u{2502} \u{251c} v4").style(black))
            .child(TextView::new(" \u{2502} \u{251c} v6").style(black))
            .child(TextView::new(" \u{251c} forwarding").style(black))
            .child(TextView::new(" \u{2502} \u{251c} v4").style(black))
            .child(TextView::new(" \u{2502} \u{2514} v6").style(black))
            .child(TextView::new(" \u{2514} local deliver").style(black))
            .child(TextView::new("   \u{251c} v4").style(black))
            .child(TextView::new("   \u{2514} v6").style(black))
            .child(DummyView)
            .child(TextView::new("TOTAL").style(black));

        let mut cols = LinearLayout::horizontal()
            .child(description_col)
            .child(DummyView.fixed_width(5));

        for cpuid in 0..num_cpus {
            let (view, map) = Self::cpu_col(format!("CPU{cpuid}"));

            cols.add_child(view);
            text_contents.push(map);
        }

        // Add the cumulative column
        let (mut view, map) = Self::cpu_col("CUMULATIVE");
        let power_content = TextContent::new("N/A");
        view.add_child(TextView::new_with_content(power_content.clone()).center());
        cols.add_child(DummyView.fixed_width(5));
        cols.add_child(view);
        text_contents.push(map);

        siv.add_layer(ScrollView::new(cols));

        (siv, Self {
            text_contents,
            power_content
        })
    }

    /// Change the CPU-time fraction ([0,1]) for the specified metric of the given CPU.
    /// The value will be displayed as a percentage
    pub fn set_val(&mut self, cpuid: usize, metric: &'static str, frac: f64) -> Option<()> {
        self.text_contents
            .get(cpuid)?
            .get(metric)?
            .set_content(format!("{: >6.02}%", frac * 100.0));

        Some(())
    }

    /// Change the total networking power in Watts
    pub fn set_total_power(&mut self, w: f64) {
        self.power_content.set_content(format!("({w:.1} W)"));
    }

    /// Build the vertical LinearLayout for the cpuid'th CPU
    fn cpu_col(title: impl ToString) -> (LinearLayout, HashMap<&'static str, TextContent>) {
        let text_contents = HashMap::from([
            ("tx_syscalls", TextContent::new("N/A")),
            ("tx_softirq", TextContent::new("N/A")),
            ("rx_softirq", TextContent::new("N/A")),
            ("driver_poll", TextContent::new("N/A")),
            ("xdp_generic", TextContent::new("N/A")),
            ("tc_classify", TextContent::new("N/A")),
            ("nf_ingress", TextContent::new("N/A")),
            ("bridging", TextContent::new("N/A")),
            ("nf_prerouting_v4", TextContent::new("N/A")),
            ("nf_prerouting_v6", TextContent::new("N/A")),
            ("forwarding_v4", TextContent::new("N/A")),
            ("forwarding_v6", TextContent::new("N/A")),
            ("local_deliver_v4", TextContent::new("N/A")),
            ("local_deliver_v6", TextContent::new("N/A")),
            ("total", TextContent::new("N/A"))
        ]);
        
        let layout = LinearLayout::vertical()
            .child(
                PaddedView::lrtb(
                    2, 2,
                    0, 0,
                    TextView::new(title.to_string())
                        .center()
                        .style(Color::Rgb(0, 0, 0))
                    )
            )
            .child(DummyView)
            .child(TextView::new_with_content(text_contents["tx_syscalls"].clone()).center())
            .child(TextView::new_with_content(text_contents["tx_softirq"].clone()).center())
            .child(TextView::new_with_content(text_contents["rx_softirq"].clone()).center())
            .child(TextView::new_with_content(text_contents["driver_poll"].clone()).center())
            .child(TextView::new_with_content(text_contents["xdp_generic"].clone()).center())
            .child(TextView::new_with_content(text_contents["tc_classify"].clone()).center())
            .child(TextView::new_with_content(text_contents["nf_ingress"].clone()).center())
            .child(TextView::new_with_content(text_contents["bridging"].clone()).center())
            .child(DummyView)
            .child(TextView::new_with_content(text_contents["nf_prerouting_v4"].clone()).center())
            .child(TextView::new_with_content(text_contents["nf_prerouting_v6"].clone()).center())
            .child(DummyView)
            .child(TextView::new_with_content(text_contents["forwarding_v4"].clone()).center())
            .child(TextView::new_with_content(text_contents["forwarding_v6"].clone()).center())
            .child(DummyView)
            .child(TextView::new_with_content(text_contents["local_deliver_v4"].clone()).center())
            .child(TextView::new_with_content(text_contents["local_deliver_v6"].clone()).center())
            .child(DummyView)
            .child(TextView::new_with_content(text_contents["total"].clone()).center());

        (layout, text_contents)
    }
}
