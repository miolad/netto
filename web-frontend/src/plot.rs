use std::{borrow::Borrow, sync::OnceLock};
use metrics_common::MetricsWrapper;
use plotters::{prelude::*, coord::types::RangedCoordf32, style::{text_anchor::{Pos, HPos, VPos}, RelativeSize}};
use plotters::style::full_palette as palette;

/// Relative width of any bar w.r.t. the total drawing area's width
const BAR_WIDTH: f32 = 0.13;
/// Relative height of the bars w.r.t. the total drawing area's height
const BAR_HEIGHT: f32 = 0.8;
/// Relative size of the font w.r.t. the total drawing area's width
const FONT_SIZE: f64 = 0.02;
const FONT: &str = "monospace";

/// This is not great, but apparently computing the size of a text field scrolls the page back to the top (???)
static TEXT_HEIGHT: OnceLock<u32> = OnceLock::new();

struct BoxSpec<S> {
    fraction: f32,
    name: S,
    color: RGBAColor,
    text_color: RGBAColor
}

fn draw_stacked_bar<DB: DrawingBackend, S: Borrow<str>>(
    drawing_area: &DrawingArea<DB, Cartesian2d<RangedCoordf32, RangedCoordf32>>,
    position: (f32, f32),
    height: f32,
    stack: impl IntoIterator<Item = BoxSpec<S>>
) -> anyhow::Result<()> where <DB as DrawingBackend>::ErrorType: 'static {
    let text_style = (FONT, RelativeSize::Width(FONT_SIZE), &BLACK)
        .into_text_style(drawing_area)
        .with_anchor::<RGBAColor>(Pos {
            h_pos: HPos::Center,
            v_pos: VPos::Center
        })
        .into_text_style(drawing_area);
    let mut acc_fraction = 0.0;
    
    for BoxSpec { fraction, name, color, text_color } in stack {
        drawing_area.draw(&Rectangle::new(
            [
                (position.0, position.1 + height*acc_fraction),
                (position.0 + BAR_WIDTH, position.1 + height*(acc_fraction + fraction))
            ],
            color.filled()
        ))?;

        let section_height_px = (
            drawing_area.as_coord_spec().translate(&(0.0f32, 0.0f32)).1 -
            drawing_area.as_coord_spec().translate(&(0.0f32, fraction)).1
        ).unsigned_abs();

        if section_height_px > *TEXT_HEIGHT.get().unwrap() {
            drawing_area.draw(&Text::new(
                name,
                (position.0 + BAR_WIDTH/2.0, position.1 + height*(acc_fraction + fraction / 2.0)),
                &text_style.color(&text_color)
            ))?;
        }

        acc_fraction += fraction;
    }
    
    Ok(())
}

fn draw_bar0<DB: DrawingBackend>(
    drawing_area: &DrawingArea<DB, Cartesian2d<RangedCoordf32, RangedCoordf32>>,
    metrics: &MetricsWrapper
) -> anyhow::Result<()> where <DB as DrawingBackend>::ErrorType: 'static {
    let kernel = (metrics.procfs_metrics[2] +
        metrics.procfs_metrics[5] +
        metrics.procfs_metrics[6]) / metrics.num_possible_cpus as f64;
    let user = (metrics.procfs_metrics[0] + metrics.procfs_metrics[1]) / metrics.num_possible_cpus as f64;
    let idle = 1.0 - (kernel + user);

    draw_stacked_bar(
        drawing_area,
        (0.16 - BAR_WIDTH/2.0, 0.5 - BAR_HEIGHT/2.0),
        BAR_HEIGHT,
        [
            BoxSpec {
                name: "kernel",
                fraction: kernel as _,
                color: RED.mix(0.6),
                text_color: WHITE.into()
            },
            BoxSpec {
                name: "user",
                fraction: user as _,
                color: GREEN.mix(0.6),
                text_color: BLACK.into()
            },
            BoxSpec {
                name: "idle",
                fraction: idle as _,
                color: BLACK.mix(0.2),
                text_color: BLACK.into()
            }
        ]
    )?;

    drawing_area.draw(&Text::new(
        "0%",
        (0.16 - BAR_WIDTH/2.0 - 0.01, 0.5 - BAR_HEIGHT/2.0),
        (FONT, RelativeSize::Width(FONT_SIZE), &BLACK)
            .into_text_style(drawing_area)
            .with_anchor::<RGBAColor>(Pos {
                h_pos: HPos::Right,
                v_pos: VPos::Center
            })
            .into_text_style(drawing_area)
    ))?;
    drawing_area.draw(&Text::new(
        "100%",
        (0.16 - BAR_WIDTH/2.0 - 0.01, 0.5 + BAR_HEIGHT/2.0),
        (FONT, RelativeSize::Width(FONT_SIZE), &BLACK)
            .into_text_style(drawing_area)
            .with_anchor::<RGBAColor>(Pos {
                h_pos: HPos::Right,
                v_pos: VPos::Center
            })
            .into_text_style(drawing_area)
    ))?;
    
    Ok(())
}

fn draw_bar1<DB: DrawingBackend>(
    drawing_area: &DrawingArea<DB, Cartesian2d<RangedCoordf32, RangedCoordf32>>,
    metrics: &MetricsWrapper
) -> anyhow::Result<f64> where <DB as DrawingBackend>::ErrorType: 'static {
    let networking = metrics.top_level_metrics
        .iter()
        .map(|m| m.cpu_fracs.iter().sum::<f64>())
        .sum::<f64>() / metrics.num_possible_cpus as f64;
    let kernel = (metrics.procfs_metrics[2] +
        metrics.procfs_metrics[5] +
        metrics.procfs_metrics[6]) / metrics.num_possible_cpus as f64;
    let kernel_adjusted = kernel.max(networking);
    
    let colors = [
        (palette::ORANGE_400.into(), BLACK.into()), // TX syscalls
        (CYAN.into(), BLACK.into()),                // TX softirq
        (palette::PURPLE.into(), WHITE.into()),     // RX softirq
        (BLACK.mix(0.2), BLACK.into())              // other
    ];
    let stack = metrics.top_level_metrics
        .iter()
        .map(|m| (m.name.as_str(), m.cpu_fracs.iter().sum::<f64>() / (metrics.num_possible_cpus as f64 * kernel_adjusted)))
        .chain(std::iter::once(
            ("other", (kernel_adjusted - networking) / kernel_adjusted)
        ))
        .zip(colors.into_iter())
        .map(|((name, fraction), (color, text_color))| BoxSpec {
            name, fraction: fraction as _, color, text_color
        });

    draw_stacked_bar(
        drawing_area,
        (0.5 - BAR_WIDTH/2.0, 0.5 - BAR_HEIGHT/2.0),
        BAR_HEIGHT,
        stack
    )?;

    drawing_area.draw(&PathElement::new(
        [
            (0.16 + BAR_WIDTH/2.0, 0.5 + (kernel as f32 - 0.5)*BAR_HEIGHT),
            (0.5 - BAR_WIDTH/2.0, 0.5 + BAR_HEIGHT/2.0)
        ],
        BLACK
    ))?;
    drawing_area.draw(&PathElement::new(
        [
            (0.16 + BAR_WIDTH/2.0, 0.5 - BAR_HEIGHT/2.0),
            (0.5 - BAR_WIDTH/2.0, 0.5 - BAR_HEIGHT/2.0)
        ],
        BLACK
    ))?;
    
    Ok(kernel_adjusted)
}

fn draw_bar2<DB: DrawingBackend>(
    drawing_area: &DrawingArea<DB, Cartesian2d<RangedCoordf32, RangedCoordf32>>,
    metrics: &MetricsWrapper,
    kernel_adjusted: f64
) -> anyhow::Result<()> where <DB as DrawingBackend>::ErrorType: 'static {
    let rx_softirq_metric = metrics.top_level_metrics
        .iter()
        .find(|m| m.name == "RX softirq")
        .unwrap();

    let colors = [
        (palette::LIGHTGREEN_A700.into(), BLACK.into()), // Driver poll
        (palette::INDIGO_A200.into(), WHITE.into()),     // GRO overhead
        (palette::PINK_A100.into(), BLACK.into()),       // XDP generic
        (palette::BLUEGREY.into(), WHITE.into()),        // TC classify
        (palette::AMBER.into(), BLACK.into()),           // NF ingress
        (palette::GREEN_200.into(), BLACK.into()),       // NF conntrack
        (palette::DEEPPURPLE.into(), WHITE.into()),      // Bridging
        (palette::BROWN_200.into(), BLACK.into()),       // NF prerouting/v4
        (palette::BROWN_A700.into(), WHITE.into()),      // NF prerouting/v6
        (palette::BLUE_200.into(), BLACK.into()),        // Forwarding/v4
        (palette::BLUE_A700.into(), WHITE.into()),       // Forwarding/v6
        (palette::RED_200.into(), BLACK.into()),         // Local delivery/v4
        (palette::RED_A400.into(), WHITE.into()),        // Local delivery/v6
        (BLACK.mix(0.2), BLACK.into())                   // other
    ];
    let sub_metrics = rx_softirq_metric.sub_metrics
        .iter()
        .flat_map(|s| if s.cpu_fracs.len() == metrics.num_possible_cpus {
            vec![(s.name.clone(), s.cpu_fracs.iter().sum::<f64>() / metrics.num_possible_cpus as f64)]
        } else {
            s.sub_metrics
                .iter()
                .map(|ss| (format!("{}/{}", s.name, ss.name), ss.cpu_fracs.iter().sum::<f64>() / metrics.num_possible_cpus as f64))
                .collect()
        });

    let total_calc = sub_metrics
        .clone()
        .map(|(_, f)| f)
        .sum::<f64>();
    let total_meas = rx_softirq_metric
        .cpu_fracs
        .iter()
        .sum::<f64>() / metrics.num_possible_cpus as f64;
    let total = total_meas.max(total_calc);
    let other = total - total_calc;
    
    let stack = sub_metrics
        .chain(std::iter::once(
            ("other".to_string(), other)
        ))
        .zip(colors.into_iter())
        .map(|((name, fraction), (color, text_color))| BoxSpec {
            name, fraction: (fraction / total) as _, color, text_color
        });

    draw_stacked_bar(
        drawing_area,
        (0.83 - BAR_WIDTH/2.0, 0.5 - BAR_HEIGHT/2.0),
        BAR_HEIGHT,
        stack
    )?;

    let mut rx_softirq_height = 0.0;
    for m in &metrics.top_level_metrics {
        if m.name == "RX softirq" {
            break;
        }
        rx_softirq_height += m.cpu_fracs.iter().sum::<f64>() / metrics.num_possible_cpus as f64;
    }

    drawing_area.draw(&PathElement::new(
        [
            (0.5 + BAR_WIDTH/2.0, 0.5 + (((rx_softirq_height + total_meas) / kernel_adjusted) as f32 - 0.5)*BAR_HEIGHT),
            (0.83 - BAR_WIDTH/2.0, 0.5 + BAR_HEIGHT/2.0)
        ],
        BLACK
    ))?;
    drawing_area.draw(&PathElement::new(
        [
            (0.5 + BAR_WIDTH/2.0, 0.5 + ((rx_softirq_height / kernel_adjusted) as f32 - 0.5)*BAR_HEIGHT),
            (0.83 - BAR_WIDTH/2.0, 0.5 - BAR_HEIGHT/2.0)
        ],
        BLACK
    ))?;
    
    Ok(())
}

pub fn update_plot<DB: DrawingBackend>(
    drawing_area: &DrawingArea<DB, Cartesian2d<RangedCoordf32, RangedCoordf32>>,
    metrics: &MetricsWrapper
) -> anyhow::Result<()> where <DB as DrawingBackend>::ErrorType: 'static {
    let _ = TEXT_HEIGHT.get_or_init(|| {
        drawing_area.estimate_text_size("A", &(FONT, RelativeSize::Width(FONT_SIZE), &BLACK)
            .into_text_style(drawing_area)
            .with_anchor::<RGBAColor>(Pos {
                h_pos: HPos::Center,
                v_pos: VPos::Center
            })
            .into_text_style(drawing_area)
        ).unwrap().1
    });
    
    // Clear the plot
    drawing_area.fill(&WHITE)?;
    
    draw_bar0(drawing_area, metrics)?;
    let kernel_adjusted = draw_bar1(drawing_area, metrics)?;
    draw_bar2(drawing_area, metrics, kernel_adjusted)?;

    Ok(())
}
