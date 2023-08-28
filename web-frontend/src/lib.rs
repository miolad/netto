mod plot;
mod table;

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
    let document = window.document().expect("Failed to get a reference to the document object");
    let table = document.query_selector("#metrics-table")?.expect("Failed to find main table element in document");
    let overhead_element = document.query_selector("#overhead")?.expect("Failed to find user-space overhead element in document");
    let power_element = document.query_selector("#power")?.expect("Failed to find power draw element in document");
    let procfs_table = document.query_selector("#procfs-table")?.expect("Failed to find procfs table in document");

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

    let svg_container = document.query_selector("#svg-container")?.expect("Failed to find svg container in document");
    let mut svg_buf = String::new();
    
    let onmessage_callback = Closure::<dyn FnMut(_) -> _>::new(move |e: MessageEvent| -> Result<(), JsValue> {
        if let Ok(text) = e.data().dyn_into::<js_sys::JsString>() {
            let text = <js_sys::JsString as ToString>::to_string(&text);

            if let Ok(metrics) = MetricsWrapper::from_json(&text) {
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
                svg_buf.clear();

                // Update main metrics table
                build_table(&document, &table, metrics)?;
            } else {
                console::log_1(&"Received invalid text message".into());
            }
        }

        Ok(())
    });
    
    ws.set_onmessage(Some(onmessage_callback.as_ref().unchecked_ref()));
    onmessage_callback.forget();

    Ok(())
}
