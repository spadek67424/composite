use serde_derive::Deserialize;
use serde_json::{self, Value};
use std::collections::HashMap;
use std::process::Command;

#[derive(Debug, Deserialize)]
struct Entry {
    address: String,
    usize: i32,
    #[serde(default)] // Default dependencies is 0 if missing
    dependencies: Vec<String>,
}

fn main() {
    let binary = "/home/minghwu/work/composite/system_binaries/cos_build-pingpong/global.ping/tests.unit_pingpong.global.ping";
    let entry_function = "__cosrt_c_pong_subset";
    // Execute the Python script
    let output = Command::new("python3")
        .arg("/home/minghwu/work/composite/tools/pyelftool_parser/src/analyzer.py")
        .arg(binary)
        .arg(entry_function)
        .output()
        .expect("Failed to execute Python script");

    // Check for script errors
    if !output.status.success() {
        eprintln!("Python script execution failed with status: {}", output.status);
        if !output.stderr.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            eprintln!("Error output from Python script: {}", stderr);
        }
        std::process::exit(1);
    }

    // Ensure output is valid UTF-8
    let stdout: String = match String::from_utf8(output.stdout) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Invalid UTF-8 output from Python script: {}", e);
            return;
        }
    };

    println!("Raw JSON output:\n{}", stdout);

    // Parse JSON dynamically as a HashMap
    let json_value: HashMap<String, Value> = match serde_json::from_str(&stdout) {
        Ok(val) => val,
        Err(e) => {
            eprintln!("Failed to parse JSON: {}", e);
            eprintln!("Raw JSON output that caused failure:\n{}", stdout);
            return;
        }
    };

    // Find the first key (assuming there's only one top-level entry)
    if let Some((key, value)) = json_value.into_iter().next() {
        println!("Detected entry name: {}", key);

        // Try to deserialize into `CosrtUpcallEntry`
        match serde_json::from_value::<CosrtUpcallEntry>(value) {
            Ok(parsed) => println!("Parsed JSON:\n{:#?}", parsed),
            Err(e) => {
                eprintln!("Failed to deserialize into CosrtUpcallEntry: {}", e);
            }
        }
    } else {
        eprintln!("JSON output is empty or malformed.");
    }
}