use passes::{
    component, deps, BuildState, ComponentId, InvocationsPass, SInv, SystemState, TransitionIter,
};
use std::collections::{HashMap, HashSet};


pub struct Invocations {
    invs: Vec<SInv>,
}

fn sinvs_generate(id: &ComponentId, s: &SystemState) -> Result<Vec<SInv>, String> {
    let mut invs = Vec::new();
    let mut errors = String::from("");
    let pydep = s.get_graph(id).py_deps();
    println!("tttttttt");
    println!("{:#?}", pydep);
    let white_list = vec![
    // "tmrmgr_start".to_string(),
    // "tmrmgr_evt_get".to_string(),
    // "tmrmgr_stop".to_string(),
    // "tmrmgr_create".to_string(),
    // "tmrmgr_evt_set".to_string(),
    // "tmrmgr_delete".to_string(),
    // "__evt_trigger".to_string(),
    // "__evt_get".to_string(),
    // "__evt_alloc".to_string(),
    // "__evt_free".to_string(),
    // "__evt_add".to_string(),
    // "__evt_rem".to_string(),
        // "sched_thd_wakeup".to_string(),
        // "sched_blkpt_trigger".to_string(),
        // "sched_blkpt_free".to_string(),
        // "sched_thd_block".to_string(),
        // "sched_aep_create_closure".to_string(),
        // "sched_thd_create_closure".to_string(),
        // "sched_thd_delete".to_string(),
        // "sched_blkpt_block".to_string(),
        // "sched_blkpt_alloc".to_string(),
        // "sched_thd_param_set".to_string(),
        // "sched_set_tls".to_string(),
        // "sched_debug_thd_state".to_string(),
        // "sched_thd_exit".to_string(),
        // "sched_thd_yield_to".to_string(),
        // "sched_get_cpu_freq".to_string(),
        // "capmgr_create_noop".to_string(),
        // "capmgr_vm_vmcs_create".to_string(),
        // "capmgr_vm_shared_region_create".to_string(),
        // "capmgr_vm_msr_bitmap_create".to_string(),
        // "capmgr_vm_vmcb_create".to_string(),
        
        // "capmgr_vm_comp_create".to_string(),
        // "capmgr_vm_vcpu_create".to_string(),
        // "capmgr_vm_lapic_create".to_string(),
        // "capmgr_initthd_create".to_string(),
        // "capmgr_vm_lapic_access_create".to_string(),
        // "capmgr_vm_shared_kernel_page_create_at".to_string(),
        // "capmgr_aep_create_thunk".to_string(),
        // "capmgr_shared_kernel_page_create".to_string(),
        // "capmgr_asnd_create".to_string(),
        // "capmgr_thd_create_ext".to_string(),
        "capmgr_asnd_rcv_create".to_string(),
        "capmgr_initaep_create".to_string(),
        "capmgr_aep_create_ext".to_string(),
        "capmgr_set_tls".to_string(),
        "capmgr_asnd_key_create".to_string(),
        "memmgr_shared_page_map_aligned".to_string(),
        "memmgr_shared_page_allocn".to_string(),
        "memmgr_map_phys_to_virt".to_string(),
        "memmgr_shared_page_map".to_string(),
        "memmgr_shared_page_map_aligned_in_vm".to_string(),
        "memmgr_heap_page_allocn_aligned".to_string(),
        "memmgr_virt_to_phys".to_string(),

    ];
    // find each undefined symbol
    for (sname, symbinfo) in s.get_objs_id(id).client_symbs() {
        let mut found = false;
        if !pydep.contains(&format!("__cosrt_c_{}", sname)) && !pydep.contains(&format!("__cosrt_extern_{}", sname)) && !pydep.contains(sname)  && !sname.contains("init_exit") && !sname.contains("addr_get") && !white_list.contains(sname) { //&& !sname.contains("capmgr") { //&&  !white_list.contains(sname) { // {
            println!("sname is not find in pydep: {}", sname);
            continue;
        }
        for d in deps(&s, &id) {
            // find the correct dependency (whose interface
            // prefixes the symbol)
            if !sname.trim_matches('_').starts_with(&d.interface) {
                continue;
            }

            let srv_id = s
                .get_named()
                .ids()
                .iter()
                .filter_map(|(id, name)| if *name == d.server { Some(id) } else { None })
                .next()
                .unwrap();
            match s.get_objs_id(srv_id).server_symbs().get(sname) {
                Some(ref srv_symbs) => {
                    invs.push(SInv {
                        symb_name: sname.clone(),
                        client: id.clone(),
                        server: srv_id.clone(),
                        c_fn_addr: symbinfo.func_addr.clone(),
                        c_callgate_addr: symbinfo.callgate_addr.clone(),
                        c_ucap_addr: symbinfo.ucap_addr.clone(),
                        s_fn_addr: srv_symbs.func_addr.clone(),
                        s_altfn_addr: srv_symbs.altfn_addr.clone(),
                    });
                    found = true;
                }
                None => continue,
            }
        }

        if !found {
            let mut aggdeps = String::from("");
            for d in deps(&s, &id) {
                aggdeps.push_str(&format!(" {}", d.server.clone()));
            }

            errors.push_str(&format!(
                r#"Error: Undefined dependency for unresolved function.  Component {} has an undefined function call to {} that is not satisfied by any of its dependencies (i.e. that function isn't provided by any of{}).\nReasons this could happen include:\n- None of the dependent servers provide that function. Make sure to include a function that exports an interface with {}.\n- The stubs in one of the servers don't properly export the function (search for __crt_s_{} in the server's exported symbols using `nm` or `objdump`) to see if this is the problem.\n- Every function in an interface must have a namespace matching the interface name (interface "pong" must only export functions named "pong_*"). Make sure that your functions are properly named in the interface.\n"#,
                component(&s, &id).name, sname, aggdeps, sname, sname));
        }
    }

    if errors.len() > 0 {
        return Err(errors);
    }

    Ok(invs)
}

impl TransitionIter for Invocations {
    fn transition_iter(
        id: &ComponentId,
        s: &SystemState,
        _b: &mut dyn BuildState,
        py_entry: &mut HashMap<ComponentId, HashSet<String>>,
    ) -> Result<Box<Self>, String> {
        let curr = s.get_named().ids().get(id).unwrap();
        let mut invs = Vec::new();
        let mut temp = 0;
        for cid in s
            .get_named()
            .ids()
            .iter()
            .map(|(cid, _)| cid)
            .filter(|cid| {
                let c = component(&s, &cid);
                c.constructor == *curr
            })
        {
            // Should be true as constructor relationships should be
            // factored into the component id total order
            assert!(cid > id);
            println!("gggggg {}", temp);
            temp += 1;
            println!("{:#?}", _b.comp_obj_path(&cid, &s)?);
            invs.append(&mut (sinvs_generate(cid, s)?));
        }

        Ok(Box::new(Invocations { invs }))
    }
}

impl InvocationsPass for Invocations {
    fn invocations(&self) -> &Vec<SInv> {
        &self.invs
    }
}
