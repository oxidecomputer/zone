// Copyright 2021 Oxide Computer Company

use std::path::Path;
use zone::{Adm, Config, CreationOptions, Zlogin};

const PFEXEC: &str = "/bin/pfexec";

// This test is marked with ignore because it involves booting a newly created
// zone which can take over a minute. This test assumes that the sparse brand is
// installed, if not use `pkg install brand/sparse`.
#[test]
#[ignore]
fn test_zlogin() {
    // Setup zfs pool for zone.
    zfs_zonetest_create();

    let name = "zexec";
    let path = Path::new("/zonetest/zexec");

    // Create a zone.
    let mut cfg = Config::create(name, true, CreationOptions::Default);
    cfg.get_global()
        .set_path(path)
        .set_autoboot(true)
        .set_brand("sparse");
    cfg.run().unwrap();

    // Install and boot zone, cleaning up on failure.
    let mut adm = Adm::new(name);
    adm.install(&[]).unwrap_or_else(|e| {
        cfg.delete(true).run().unwrap();
        zfs_zonetest_destroy();
        panic!("{}", e);
    });
    adm.boot().unwrap_or_else(|e| {
        adm.uninstall(true).unwrap();
        cfg.delete(true).run().unwrap();
        zfs_zonetest_destroy();
        panic!("{}", e);
    });

    // Run the `hostname` command in the zone.
    let zlogin = Zlogin::new(name);
    let out = zlogin.exec("hostname").unwrap_or_else(|e| {
        adm.halt().unwrap();
        adm.uninstall(true).unwrap();
        cfg.delete(true).run().unwrap();
        zfs_zonetest_destroy();
        panic!("{}", e);
    });

    // Run a command that should fail in the zone.
    let bad_result = zlogin.exec("/usr/bin/notathing");

    // Destroy the zone.
    adm.halt().unwrap();
    adm.uninstall(true).unwrap();
    cfg.delete(true).run().unwrap();
    zfs_zonetest_destroy();

    // Running `hostname` within the zone should yield the name of the zone.
    assert_eq!(out, "zexec");

    // Running a bad command should yield an error.
    match bad_result {
        Ok(_) => panic!("expected error for bad command"),

        // The exact content of the error will depend on the shell.
        Err(e) => println!("got error: {:?}", e),
    }
}

// Create a ZFS pool called zonetest.
fn zfs_zonetest_create() {
    std::process::Command::new(PFEXEC)
        .env_clear()
        .arg("zfs")
        .arg("create")
        .arg("-p")
        .arg("-o")
        .arg("mountpoint=/zonetest")
        .arg("rpool/zonetest")
        .output()
        .unwrap();
}

// Destroy the zonetest zfs pool.
fn zfs_zonetest_destroy() {
    std::process::Command::new(PFEXEC)
        .env_clear()
        .arg("zfs")
        .arg("destroy")
        .arg("-rf")
        .arg("rpool/zonetest")
        .output()
        .unwrap();
}
