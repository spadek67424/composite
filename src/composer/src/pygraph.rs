use std::collections::{HashMap, HashSet};
use std::process::Command;
use passes::{
    BuildState, ComponentId, PyPass, SystemState, TransitionIter,
};

#[derive(Debug, Deserialize)]
pub struct Entry {
    entry_function: String,
    address: String,
    stacksize: usize,
    #[serde(default)] // Default dependencies is 0 if missing
    dependencies: Vec<String>,
}

pub struct Pydependency {
    pygraph: HashMap<String, Entry>,
    pydeps: HashSet<String>,
}

impl TransitionIter for Pydependency {
    fn transition_iter(
        id: &ComponentId,
        s: &SystemState,
        b: &mut dyn BuildState,
    ) -> Result<Box<Self>, String> {
        let binary = b.comp_obj_path(&id, &s)?;
        let entry_function = s.get_objs_id(id).server_symbs().keys();
        // println!("aaaaaaaa");  
        // println!("{}",binary);
        let mut keys_vec = Vec::new();
        for i in entry_function {
            // println!("{:#?}", i);
            // println!("ccccccc"); 
            keys_vec.push("__cosrt_s_".to_owned() + &i.clone()); // Convert &String to String
        }
        keys_vec.push("__cosrt_upcall_entry".to_owned());
        let joined_args = keys_vec.join(","); // Convert Vec<String> -> "arg1 arg2 arg3 ..."
        // Execute the Python script
        println!("entry_function : {:#?}", joined_args);
        let output = Command::new("python3")
            .arg("/home/minghwu/work/composite/tools/pyelftool_parser/src/analyzer.py")
            .arg(binary)
            .arg(joined_args)
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
        let json_value: Vec<Entry> =
            serde_json::from_str(&stdout).map_err(|e| {
                format!(
                    "Failed to parse JSON: {}\nRaw JSON output that caused failure:\n{}",
                    e, stdout
                )
            })?;
        let pygraph: HashMap<String, Entry> = json_value
        .into_iter()
        .map(|entry| (entry.entry_function.clone(), entry))
        .collect();
        
        // Union all dependencies
        let mut all_dependencies: HashSet<String> = HashSet::new();
        for entry in pygraph.values() {
            all_dependencies.extend(entry.dependencies.iter().cloned());
        }
        println!("Dependencies: {:#?}", all_dependencies);
        // Return Pydependency wrapped in Box
        Ok(Box::new(Pydependency { pygraph, pydeps: all_dependencies }))
    }
}

impl PyPass for Pydependency {
    fn py_graph(&self) -> &HashMap<String, Entry> {
        &self.pygraph
    }
    fn py_deps(&self) -> &HashSet<String> {
        &self.pydeps
    }
}