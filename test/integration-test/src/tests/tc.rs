use std::process::Command;

use aya::{
    Ebpf,
    programs::{
        SchedClassifier, TcAttachType,
        tc::{ClassId, NlOptions, TcAttachOptions, qdisc_add_clsact},
    },
};

use crate::utils::NetNsGuard;

#[test_log::test]
fn test_tc_classid() {
    let _netns = NetNsGuard::new();
    let iface = "lo";

    let mut bpf = Ebpf::load(crate::TCX).expect("Failed to load eBPF");
    let program: &mut SchedClassifier = bpf
        .program_mut("tcx_next")
        .unwrap()
        .try_into()
        .expect("Failed to get SchedClassifier");

    program.load().expect("Failed to load program into kernel");

    qdisc_add_clsact(iface).expect("Failed to add clsact qdisc");

    let opts = NlOptions {
        classid: Some(ClassId::from_parts(1, 10)),
        ..Default::default()
    };

    let link_id = program
        .attach_with_options(iface, TcAttachType::Ingress, TcAttachOptions::Netlink(opts))
        .expect("Failed to attach TC program with classid");

    let link = program.take_link(link_id).expect("Failed to take link");

    assert_eq!(
        link.classid().expect("Failed to get classid"),
        Some(ClassId::from_parts(1, 10)),
    );

    let output = Command::new("tc")
        .args(["filter", "show", "dev", iface, "ingress"])
        .output()
        .expect("Failed to execute tc command");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("flowid 1:a"),
        "Kernel ignored the classid! Output was:\n{stdout}",
    );
}
