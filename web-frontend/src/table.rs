use metrics_common::{Metric, MetricsWrapper};
use wasm_bindgen::JsValue;
use web_sys::{Document, Element};

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
pub fn build_table(document: &Document, table: &Element, metrics: MetricsWrapper) -> Result<(), JsValue> {
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