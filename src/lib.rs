use anyhow::{Context as _, Result};
use binaryninja::{
    binary_view::{BinaryView, BinaryViewExt},
    command::{self, Command},
    logger::Logger,
};
use log::{error, info};
use pdb_sdk::Guid;
use pdb_sdk::builders::PdbBuilder;
use pdb_sdk::dbi::SectionHeader;
use std::io::BufWriter;
use std::path::PathBuf;
use std::{collections::HashMap, fs};

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

    let mut builder = PdbBuilder::default();
    builder.info().guid(Guid(pdb_info.guid));
    builder.info().age(pdb_info.age);
    builder.info().signature(pdb_info.timestamp);

    build_sections(view, &mut builder)?;

    let exe_path = PathBuf::from(view.file().filename());
    let pdb_path = exe_path.with_extension("pdb");

    info!("Writing PDB to: {}", pdb_path.display());

    let output = BufWriter::new(fs::File::create(&pdb_path)?);
    builder.commit(output)?;

    info!("PDB written successfully to: {}", pdb_path.display());

    Ok(())
}

fn build_sections(view: &BinaryView, builder: &mut PdbBuilder) -> Result<()> {
    let section_headers_sym = view
        .symbol_by_raw_name("__section_headers")
        .context("could not find __section_headers symbol")?;

    let section_headers_array = view
        .data_variable_at_address(section_headers_sym.address())
        .context("could not find section headers data variable")?
        .ty
        .contents;

    let num_sections = section_headers_array.count();

    let section_header_type = section_headers_array
        .child_type()
        .context("could not get section header type")?
        .contents
        .get_named_type_reference()
        .context("could not get named type reference")?
        .target(view)
        .context("could not resolve type reference")?;

    let section_header_struct = section_header_type
        .get_structure()
        .context("Section_Header is not a structure type")?;

    let member_offsets: std::collections::HashMap<String, u64> = section_header_struct
        .members()
        .iter()
        .map(|m| (m.name.to_string(), m.offset))
        .collect();

    let section_headers_addr = section_headers_sym.address();
    let section_header_size = section_header_type.width();

    for i in 0..num_sections {
        let header_addr = section_headers_addr + i * section_header_size;

        let mut name = [0u8; 8];
        let name_offset = member_offsets.get("name").context("missing 'name' field")?;
        let name_bytes = view.read_vec(header_addr + name_offset, 8);
        name.copy_from_slice(&name_bytes[..8]);

        let virtual_size = read_u32_field(view, header_addr, &member_offsets, "virtualSize")?;
        let virtual_address = read_u32_field(view, header_addr, &member_offsets, "virtualAddress")?;
        let size_of_raw_data = read_u32_field(view, header_addr, &member_offsets, "sizeOfRawData")?;
        let pointer_to_raw_data =
            read_u32_field(view, header_addr, &member_offsets, "pointerToRawData")?;
        let pointer_to_relocations =
            read_u32_field(view, header_addr, &member_offsets, "pointerToRelocations")?;
        let pointer_to_line_numbers =
            read_u32_field(view, header_addr, &member_offsets, "pointerToLineNumbers")?;
        let number_of_relocations =
            read_u16_field(view, header_addr, &member_offsets, "numberOfRelocations")?;
        let number_of_line_numbers =
            read_u16_field(view, header_addr, &member_offsets, "numberOfLineNumbers")?;
        let characteristics =
            read_u32_field(view, header_addr, &member_offsets, "characteristics")?;

        let name_str = std::str::from_utf8(&name)
            .unwrap_or("<invalid>")
            .trim_end_matches('\0');
        info!("Adding section: {name_str} (VA: 0x{virtual_address:x}, Size: 0x{virtual_size:x})",);

        builder.dbi().add_section_header(SectionHeader {
            name,
            virtual_size,
            virtual_address,
            size_of_raw_data,
            pointer_to_raw_data,
            pointer_to_relocations,
            pointer_to_line_numbers,
            number_of_relocations,
            number_of_line_numbers,
            characteristics,
        });
    }

    Ok(())
}

fn read_u32_field(
    view: &BinaryView,
    base_addr: u64,
    offsets: &HashMap<String, u64>,
    field_name: &str,
) -> Result<u32> {
    let offset = offsets
        .get(field_name)
        .context(format!("missing '{field_name}' field"))?;
    let bytes = view.read_vec(base_addr + offset, 4);
    Ok(u32::from_le_bytes(bytes.try_into().unwrap()))
}

fn read_u16_field(
    view: &BinaryView,
    base_addr: u64,
    offsets: &HashMap<String, u64>,
    field_name: &str,
) -> Result<u16> {
    let offset = offsets
        .get(field_name)
        .context(format!("missing '{field_name}' field"))?;
    let bytes = view.read_vec(base_addr + offset, 2);
    Ok(u16::from_le_bytes(bytes.try_into().unwrap()))
}
