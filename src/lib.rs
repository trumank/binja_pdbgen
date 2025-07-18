use anyhow::{Context as _, Result};
use binaryninja::{
    binary_view::{BinaryView, BinaryViewExt},
    command::{self, Command},
    logger::Logger,
};
use log::{error, info};

#[unsafe(no_mangle)]
pub extern "C" fn CorePluginInit() -> bool {
    Logger::new("pdbgen").init();

    info!("pdbgen loaded");

    command::register_command("Generate PDB", "Generate PDB for .exe", GenPdb {});

    true
}

struct GenPdb {}
impl Command for GenPdb {
    fn action(&self, view: &BinaryView) {
        match gen_pdb(view) {
            Ok(_) => info!("PDB generated successfully"),
            Err(err) => error!("PDB generation failed {err:?}"),
        };
    }

    fn valid(&self, view: &BinaryView) -> bool {
        // Check if this is a PE file and has the necessary symbols
        view.view_type() == "PE"
            && !view.symbols_by_name("__coff_header").is_empty()
            && !view.symbols_by_name("PDBGuid").is_empty()
            && !view.symbols_by_name("PDBAge").is_empty()
    }
}

#[derive(Debug)]
struct PdbInfo {
    age: u32,
    timestamp: u32,
    guid: [u8; 16],
}

fn get_pdbinfo(view: &BinaryView) -> Result<PdbInfo> {
    let coff_header_sym = view
        .symbol_by_raw_name("__coff_header")
        .context("could not find __coff_header symbol")?;
    let pdb_age_sym = view
        .symbol_by_raw_name("PDBAge")
        .context("could not find PDBAge symbol")?;
    let pdb_guid_sym = view
        .symbol_by_raw_name("PDBGuid")
        .context("could not find PDBGuid symbol")?;

    let timestamp_bytes = view.read_vec(coff_header_sym.address() + 0x8, 4);
    let timestamp = u32::from_le_bytes(timestamp_bytes.try_into().unwrap());

    let age_bytes = view.read_vec(pdb_age_sym.address(), 4);
    let age = u32::from_le_bytes(age_bytes.try_into().unwrap());

    let guid_bytes = view.read_vec(pdb_guid_sym.address(), 16);
    let guid = guid_bytes.try_into().unwrap();

    Ok(PdbInfo {
        age,
        timestamp,
        guid,
    })
}

fn gen_pdb(view: &BinaryView) -> Result<()> {
    let pdb_info = get_pdbinfo(view)?;
    info!("PdbInfo = {pdb_info:?}");
    Ok(())
}
