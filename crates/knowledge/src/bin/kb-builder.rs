//! Converts DuckDuckGo's tracker list into `data/sources/ddg_trackers.json`.
//! Run through `scripts/update-tracker-list.ps1`, which downloads the list.
//!
//! Usage: kb-builder <extension-tds.json> <output.json>

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [input, output] = args.as_slice() else {
        eprintln!("usage: kb-builder <extension-tds.json> <output.json>");
        std::process::exit(2);
    };
    let result = std::fs::read_to_string(input)
        .map_err(|e| format!("cannot read {input}: {e}"))
        .and_then(|tds| ga_knowledge::ddg::convert(&tds, ga_knowledge::BUNDLED_SEED).map_err(|e| e.to_string()))
        .and_then(|json| {
            // Check the result loads together with the seed before writing it.
            ga_knowledge::TrackerDb::from_sources(&[ga_knowledge::BUNDLED_SEED, &json]).map_err(|e| e.to_string())?;
            std::fs::write(output, &json).map_err(|e| format!("cannot write {output}: {e}"))
        });
    if let Err(e) = result {
        eprintln!("kb-builder: {e}");
        std::process::exit(1);
    }
    println!("Wrote {output}");
}
