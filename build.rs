fn main() -> anyhow::Result<()> {
    let sleigh_root = std::path::PathBuf::from("sleigh");
    let sleigh_dir = sleigh_root.join("sleigh");
    let zlib_dir = sleigh_root.join("zlib");

    let src_dir = std::path::PathBuf::from("src");
    let binding_dir = src_dir.join("binding");

    let bridge_file = src_dir.join("lib.rs");

    let mut build = cxx_build::bridge(bridge_file);

    // add zlib
    for entry in std::fs::read_dir(&zlib_dir)? {
        let filename = entry.unwrap().path();
        if filename.extension().map_or(false, |ext| ext == "c" || ext == "cc") {
            build.file(filename);
        }
    }

    // add sleigh
    for entry in std::fs::read_dir(&sleigh_dir)? {
        let filename = entry.unwrap().path();
        if filename.extension().map_or(false, |ext| ext == "c" || ext == "cc") {
            build.file(filename);
        }
    }

    build
        .cpp(true)
        .std("c++17")
        .define("LOCAL_ZLIB", "1")
        .define("NO_GZIP", "1")
        .include(&sleigh_dir)
        .include(&zlib_dir)
        .include(&binding_dir)
        .compile("sleigh");
    
    println!("cargo:rerun-if-changed={}", sleigh_dir.display());
    println!("cargo:rerun-if-changed={}", zlib_dir.display());
    println!("cargo:rerun-if-changed={}", src_dir.display());

    Ok(())
}
