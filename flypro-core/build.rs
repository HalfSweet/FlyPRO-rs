use std::env;
use std::error::Error;
use std::fmt::Write as _;
use std::fs;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    println!("cargo:rerun-if-changed=assets/cfg");

    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR")?);
    let configuration_dir = manifest_dir.join("assets/cfg");
    let mut file_names = Vec::new();
    for entry in fs::read_dir(configuration_dir)? {
        let entry = entry?;
        let path = entry.path();
        if path
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("cfg"))
        {
            file_names.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    file_names.sort_by_cached_key(|name| name.to_ascii_lowercase());

    let mut source = String::from("const EMBEDDED_CONFIGURATIONS: &[EmbeddedConfiguration] = &[\n");
    for file_name in file_names {
        let stem = file_name
            .strip_suffix(".cfg")
            .or_else(|| file_name.strip_suffix(".CFG"))
            .ok_or("configuration file has no .cfg suffix")?;
        writeln!(
            source,
            "    EmbeddedConfiguration {{ stem: {stem:?}, file_name: {file_name:?}, bytes: include_bytes!(concat!(env!(\"CARGO_MANIFEST_DIR\"), \"/assets/cfg/\", {file_name:?})) }},"
        )?;
    }
    source.push_str("];\n");

    let output = PathBuf::from(env::var("OUT_DIR")?).join("embedded_configurations.rs");
    fs::write(output, source)?;
    Ok(())
}
