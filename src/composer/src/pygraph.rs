use std::collections::{HashMap, HashSet};
use std::hash::Hash;
use std::io::Write;
use std::process::Command;
use std::path::Path;
use std::fs::File;
use passes::{
    deps, BuildState, ComponentId, PyPass, SystemState, TransitionIter,
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
        py_entry: &mut HashMap<ComponentId, HashSet<String>>,
    ) -> Result<Box<Self>, String> {
        let binary = b.comp_obj_path(&id, &s)?;
        let mut all_dependencies: HashSet<String> = HashSet::new();
        let mut output_entry: HashMap<ComponentId, HashSet<String>> = HashMap::new();
        
        println!("ids : {:#?}", s.get_named().rmap());
        // println!("entry_function: {:#?}", entry_function);
        let mut keys_vec = Vec::new();
        
        if py_entry.contains_key(id) {
            for i in py_entry.get(id).unwrap().iter() {
                keys_vec.push(i.clone().replace("__cosrt_c", "__cosrt_s"));
            }
        }
        // for entry in entry_function.keys() {
        //     keys_vec.push("__cosrt_s_".to_owned() + entry);
        // }
        
        keys_vec.push("__cosrt_upcall_entry".to_owned());
        let joined_args = keys_vec.join(","); // Convert Vec<String> -> "arg1 arg2 arg3 ..."
        // Execute the Python script
        println!("join_args : {:#?}", joined_args);
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
        
        println!("pygraph: {:#?}", pygraph);
        for entry in pygraph.values() {
            all_dependencies.extend(entry.dependencies.iter().cloned());
        }
        // let mut output_entry: HashMap<ComponentId, HashSet<String>> = HashMap::new();
        for d in deps(s, id){
            println!("wwwwwww");
            println!("deps : {:#?}", d.server);
            // println!("deps sym : {:#?}", s.get_named().rmap().get(&d.server).unwrap_or(&0));
            // output_entry.insert(s.get_named().rmap().get(&d.server).unwrap_or(&0).to_owned(), all_dependencies.clone());
            match s.get_named().rmap().get(&d.server) {
                Some(server_sym) => {
                    output_entry.insert(server_sym.to_owned(), all_dependencies.clone());
                }
                None => {
                    println!("Skipping: No mapping found for server {:?}", d.server);
                }
            }
        }
        println!("output_entry : {:#?}", output_entry);

        for (key, set) in output_entry {
            py_entry.entry(key)
                .or_insert_with(HashSet::new)
                .extend(set);
        }
        println!("py_entry : {:#?}", py_entry);
        // Return Pydependency wrapped in Box
        Ok(Box::new(Pydependency { pygraph, pydeps: all_dependencies}))
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