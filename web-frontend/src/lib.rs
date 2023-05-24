use metrics_common::{MetricsWrapper, Metric};
use wasm_bindgen::prelude::*;
use web_sys::{console, WebSocket, MessageEvent, Element, Document};

#[inline]
fn empty_cell(document: &Document, element_type: &str) -> Result<Element, JsValue> {
    let td = document.create_element(element_type)?;
    td.set_text_content(Some("\u{00A0}"));
    Ok(td)
}

#[inline]
fn build_table_header(document: &Document, num_possible_cpus: usize) -> Result<Element, JsValue> {
    let row = document.create_element("tr")?;
    
    let pivot = document.create_element("th")?;
    pivot.set_text_content(Some("Metrics\\CPUs"));
    pivot.set_attribute("style", "text-align: center")?;
    row.append_child(&pivot)?;

    row.append_child(&empty_cell(document, "th")?.into())?;

    for cpuid in 0..num_possible_cpus {
        let cpu_hdr = document.create_element("th")?;
        cpu_hdr.set_text_content(Some(&format!("CPU{cpuid}")));
        cpu_hdr.set_attribute("style", "text-align: center")?;
        row.append_child(&cpu_hdr)?;
    }

    row.append_child(&empty_cell(document, "th")?.into())?;

    let cumulative = document.create_element("th")?;
    cumulative.set_text_content(Some("Cumulative"));
    cumulative.set_attribute("style", "text-align: center")?;
    row.append_child(&cumulative)?;
    
    Ok(row)
}

#[inline]
fn build_empty_row(document: &Document, num_possible_cpus: usize) -> Result<Element, JsValue> {
    let row = document.create_element("tr")?;

    for _ in 0..num_possible_cpus + 4 {
        row.append_child(&empty_cell(document, "td")?.into())?;
    }
    
    Ok(row)
}

#[inline]
fn build_values_row(document: &Document, prefix: &str, name: &str, values: &[f64], num_possible_cpus: usize) -> Result<Element, JsValue> {
    let row = document.create_element("tr")?;

    let name_cell = document.create_element("th")?;
    name_cell.set_text_content(Some(&(prefix.to_string() + name)));
    row.append_child(&name_cell)?;

    row.append_child(&empty_cell(document, "td")?.into())?;

    if values.len() == num_possible_cpus {
        let mut cumulative = 0.0;
        for v in values {
            let value_cell = document.create_element("td")?;
            value_cell.set_text_content(Some(&format!("{: >8.02}%", v * 100.0)));
            row.append_child(&value_cell)?;

            cumulative += *v;
        }
        cumulative /= values.len() as f64;

        row.append_child(&empty_cell(document, "td")?.into())?;

        let cumulative_cell = document.create_element("td")?;
        cumulative_cell.set_text_content(Some(&format!("{: >8.02}%", cumulative * 100.0)));
        row.append_child(&cumulative_cell)?;
    } else {
        for _ in 0..num_possible_cpus + 2 {
            row.append_child(&empty_cell(document, "td")?.into())?;
        }
    }

    Ok(row)
}

#[inline]
fn append_metric_row(
    document: &Document,
    prefix: &str,
    prefix_children: &str,
    table: &Element,
    metric: &Metric,
    num_possible_cpus: usize
) -> Result<(), JsValue> {
    table.append_child(
        &build_values_row(
            document,
            prefix,
            &metric.name,
            &metric.cpu_fracs,
            num_possible_cpus
        )?.into()
    )?;

    for (i, sub_metric) in metric.sub_metrics.iter().enumerate() {
        let (prefix, prefix_children) = if i < metric.sub_metrics.len() - 1 {
            (prefix_children.to_string() + " \u{251c} ", prefix_children.to_string() + " \u{2502} ")
        } else {
            (prefix_children.to_string() + " \u{2514} ", prefix_children.to_string() + "   ")
        };

        append_metric_row(
            document,
            &prefix,
            &prefix_children,
            table,
            sub_metric,
            num_possible_cpus
        )?;
    }

    Ok(())
}

#[inline]
fn build_table(document: &Document, table: &Element, metrics: MetricsWrapper) -> Result<(), JsValue> {
    table.append_child(&build_table_header(
        document,
        metrics.num_possible_cpus
    )?.into())?;

    table.append_child(&build_empty_row(
        document,
        metrics.num_possible_cpus
    )?.into())?;

    for metric in &metrics.top_level_metrics {
        append_metric_row(
            document,
            "",
            "",
            table,
            metric,
            metrics.num_possible_cpus
        )?;
    }

    table.append_child(&build_empty_row(
        document,
        metrics.num_possible_cpus
    )?.into())?;

    let total_values = metrics.top_level_metrics
        .into_iter()
        .map(|metric| metric.cpu_fracs)
        .reduce(|acc, e| {
            acc.iter()
                .zip(e.iter())
                .map(|(a, b)| a + b)
                .collect()
        });
    
    if let Some(total_values) = total_values {
        table.append_child(&build_values_row(
            document,
            "",
            "TOTAL",
            &total_values,
            metrics.num_possible_cpus
        )?.into())?;
    }
    
    Ok(())
}

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
                power_element.set_text_content(Some(&format!("{: >6.02}W", metrics.net_power_w)));

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
