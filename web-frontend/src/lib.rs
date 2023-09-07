mod plot;
mod table;

use std::sync::Arc;

use metrics_common::MetricsWrapper;
use plot::update_plot;
use table::build_table;
use wasm_bindgen::prelude::*;
use web_sys::{console, WebSocket, MessageEvent};
use plotters::{prelude::*, coord::types::RangedCoordf32};

const CANVAS_SIZE_X: f32 = 800.0;
const CANVAS_SIZE_Y: f32 = 600.0;

#[wasm_bindgen(start)]
pub fn main() -> Result<(), JsValue> {
    // Set the panic hook to print to the console
    #[cfg(feature = "console_error_panic_hook")]
    console_error_panic_hook::set_once();

    let window = web_sys::window().expect("Failed to get a reference to the window object");
    let document = Arc::new(window.document().expect("Failed to get a reference to the document object"));
    let table = Arc::new(document.query_selector("#metrics-table")?.expect("Failed to find main table element in document"));
    let overhead_element = Arc::new(document.query_selector("#overhead")?.expect("Failed to find user-space overhead element in document"));
    let power_element = Arc::new(document.query_selector("#power")?.expect("Failed to find power draw element in document"));
    let procfs_table = Arc::new(document.query_selector("#procfs-table")?.expect("Failed to find procfs table in document"));
    let svg_container = Arc::new(document.query_selector("#svg-container")?.expect("Failed to find svg container in document"));

    let ws = WebSocket::new(&(window.location().origin()?.replace("http", "ws") + "/ws/"))?;

    let procfs_metric_names = [
        "user",
        "nice",
        "system",
        "idle",
        "iowait",
        "irq",
        "softirq",
        "steal",
        "guest",
        "guest_nice"
    ];

    let mut _file_reader = None;

    let onmessage_callback = Closure::<dyn FnMut(_) -> _>::new(move |e: MessageEvent| -> Result<(), JsValue> {
        if let Ok(blob) = e.data().dyn_into::<web_sys::Blob>() {
            let blob: gloo_file::Blob = blob.into();

            let document = Arc::clone(&document);
            let table = Arc::clone(&table);
            let overhead_element = Arc::clone(&overhead_element);
            let power_element = Arc::clone(&power_element);
            let procfs_table = Arc::clone(&procfs_table);
            let svg_container = Arc::clone(&svg_container);
            
            let fr = gloo_file::callbacks::read_as_bytes(&blob, move |res| {
                if let Ok(bytes) = res {
                    if let Ok(metrics) = MetricsWrapper::from_mp(&bytes) {
                        let perform_update = || -> Result<(), JsValue> {
                            // Clear the tables
                            while let Some(child) = table.last_child() {
                                table.remove_child(&child)?;
                            }
                            while let Some(child) = procfs_table.last_child() {
                                procfs_table.remove_child(&child)?;
                            }
                            
                            // Update procfs metrics
                            for (i, procfs_metric) in metrics.procfs_metrics.iter().enumerate() {
                                let row = document.create_element("tr")?;

                                let header = document.create_element("th")?;
                                header.set_text_content(Some(procfs_metric_names[i]));
                                row.append_child(&header)?;

                                let content = document.create_element("td")?;
                                content.set_text_content(Some(&format!("{: >8.02}%", procfs_metric * 100.0)));
                                row.append_child(&content)?;

                                procfs_table.append_child(&row)?;
                            }

                            // Update isolated info
                            overhead_element.set_text_content(Some(&format!("{: >6.02}%", metrics.user_space_overhead * 100.0)));
                            power_element.set_text_content(Some(&
                                if let Some(power) = metrics.net_power_w {
                                    format!("{: >6.02}W", power)
                                } else {
                                    "  N/A".to_string()
                                }
                            ));

                            // Update plot
                            let mut svg_buf = String::new();
                            {
                                let root = SVGBackend::with_string(&mut svg_buf, (CANVAS_SIZE_X as _, CANVAS_SIZE_Y as _))
                                    .into_drawing_area()
                                    .apply_coord_spec(Cartesian2d::<RangedCoordf32, RangedCoordf32>::new(
                                        0.0..1.0f32, 0.0..1.0f32,
                                        (0..CANVAS_SIZE_X as i32, CANVAS_SIZE_Y as i32..0)
                                    ));
                                let _ = update_plot(&root, &metrics);
                            }
                            svg_container.set_inner_html(&svg_buf);

                            // Update main metrics table
                            build_table(&document, &table, metrics)?;
                            
                            Ok(())
                        };

                        if perform_update().is_err() {
                            console::log_1(&"Error while updating document".into());
                        }
                    }
                }
            });

            _file_reader = Some(fr);
        }

        Ok(())
    });
    
    ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    onmessage_callback.forget();

    Ok(())
}
