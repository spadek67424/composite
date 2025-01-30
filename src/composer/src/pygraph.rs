use serde_json::{self, Value};
use std::collections::HashMap;
use std::process::Command;
use passes::{
    BuildState, ComponentId, PyPass, SystemState, TransitionIter,
};

#[derive(Debug, Deserialize)]
struct Entry {
    address: String,
    usize: i32,
    #[serde(default)] // Default dependencies is 0 if missing
    dependencies: Vec<String>,
}

pub struct PyObject {
    pygraph: HashMap<String, Value>,
}

impl TransitionIter for PyObject {
    fn transition_iter(
        id: &ComponentId,
        s: &SystemState,
        b: &mut dyn BuildState,
    ) -> Result<Box<Self>, String> {
        let binary = "/home/minghwu/work/composite/system_binaries/cos_build-pingpong/global.ping/tests.unit_pingpong.global.ping";
        let entry_function = "__cosrt_c_pong_subset";
        // Execute the Python script
        let output = Command::new("python3")
            .arg("/home/minghwu/work/composite/tools/pyelftool_parser/src/analyzer.py")
            .arg(binary)
            .arg(entry_function)
            .output()
            .map_err(|e| format!("Failed to execute Python script: {}", e))?;
        // Check for script errors
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(format!(
                "Python script execution failed with status: {}\nError: {}",
                output.status, stderr
            ));
        }
         // Convert stdout to String
         let stdout = String::from_utf8(output.stdout)
         .map_err(|e| format!("Invalid UTF-8 output from Python script: {}", e))?;

        // Parse JSON dynamically as a HashMap
        let json_value: HashMap<String, Value> =
            serde_json::from_str(&stdout).map_err(|e| {
                format!(
                    "Failed to parse JSON: {}\nRaw JSON output that caused failure:\n{}",
                    e, stdout
                )
            })?;    
        // Return PyObject wrapped in Box
        Ok(Box::new(PyObject { pygraph: json_value }))
    }
}

impl PyPass for PyObject {
    fn py_graph(&self) -> &HashMap<String, Value> {
        &self.pygraph
    }
}