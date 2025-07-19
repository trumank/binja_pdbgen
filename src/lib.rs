use anyhow::{Context as _, Result};
use binaryninja::{
    binary_view::{BinaryView, BinaryViewBase, BinaryViewExt},
    command::{self, Command},
    logger::Logger,
};
use log::{error, info, warn};
use pdb_sdk::builders::{ModuleBuilder, PdbBuilder};
use pdb_sdk::codeview::DataRegionOffset;
use pdb_sdk::codeview::symbols::{Procedure, ProcedureProperties, SymbolRecord};
use pdb_sdk::codeview::types::{CallingConvention, FunctionProperties, TypeRecord};
use pdb_sdk::dbi::{SectionContrib, SectionHeader};
use pdb_sdk::utils::StrBuf;
use pdb_sdk::{
    Guid,
    codeview::symbols::{Public, PublicProperties},
};
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

    let section_info = build_sections(view, &mut builder)?;
    build_functions(view, &mut builder, &section_info)?;

    let filename = view.file().filename();
    let exe_path = PathBuf::from(filename.strip_suffix(".bndb").unwrap_or(&filename));
    let pdb_path = exe_path.with_extension("pdb");

    info!("Writing PDB to: {}", pdb_path.display());

    let output = BufWriter::new(fs::File::create(&pdb_path)?);
    builder.commit(output)?;

    info!("PDB written successfully to: {}", pdb_path.display());

    Ok(())
}

#[derive(Debug)]
struct SectionInfo {
    name: String,
    index: u16,
    virtual_address: u32,
    virtual_size: u32,
    characteristics: u32,
}

fn build_sections(view: &BinaryView, builder: &mut PdbBuilder) -> Result<Vec<SectionInfo>> {
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

    let mut sections = Vec::new();

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

        sections.push(SectionInfo {
            name: name_str.to_string(),
            index: (i as u16) + 1, // Section indices are 1-based in PDB
            virtual_address,
            virtual_size,
            characteristics,
        });

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

    Ok(sections)
}

fn build_functions(
    view: &BinaryView,
    builder: &mut PdbBuilder,
    sections: &[SectionInfo],
) -> Result<()> {
    let void_fn_type = {
        let tpi = builder.tpi();

        let arg_list = tpi.add(
            "args",
            TypeRecord::ArgList {
                count: 0,
                arg_list: vec![],
            },
        );

        tpi.add(
            "void_func",
            TypeRecord::Procedure {
                return_type: None,
                calling_conv: CallingConvention::NearC,
                properties: FunctionProperties::new(),
                arg_count: 0,
                arg_list,
            },
        )
    };

    let base_address = view.start();
    let mut functions_by_section: HashMap<u16, Vec<_>> = HashMap::new();

    let func_iter = view.functions();
    for function in &func_iter {
        let func_addr = function.start();

        for section in sections {
            let section_start = base_address + section.virtual_address as u64;
            let section_end = section_start + section.virtual_size as u64;

            if (section_start..section_end).contains(&func_addr) {
                functions_by_section
                    .entry(section.index)
                    .or_default()
                    .push(function);
                break;
            }
            warn!("Function 0x{func_addr:x} is not inside any section");
        }
    }

    for (section_idx, functions) in functions_by_section {
        let section = sections
            .iter()
            .find(|s| s.index == section_idx)
            .context("section not found")?;

        let section_start = base_address + section.virtual_address as u64;

        info!(
            "Creating module for section {} with {} functions",
            section.name,
            functions.len()
        );

        let sec_contrib = SectionContrib {
            i_sect: section_idx,
            pad1: [0, 0],
            offset: 0,
            size: section.virtual_size,
            characteristics: section.characteristics,
            i_mod: 0,
            pad2: [0, 0],
            data_crc: 0,
            reloc_crc: 0,
        };

        let mut module = ModuleBuilder::new(
            format!("{}_module", section.name),
            format!("/fake/path/{}.obj", section.name),
            sec_contrib,
        );

        for function in functions {
            let func_name = function.symbol().short_name();
            let func_name = func_name.to_string_lossy();

            for (i, range) in function.address_ranges().iter().enumerate() {
                let func_start = range.start;
                let func_size = range.end - range.start;
                let func_offset = (func_start - section_start) as u32;
                let func_name = if i == 0 {
                    func_name.clone()
                } else {
                    format!("{func_name}_part{}", i + 1).into()
                };

                // info!(
                //     "  Adding function: 0x{func_start:x} {func_name} at offset 0x{func_offset:x} (size: 0x{func_size:x})"
                // );

                // add to module
                let proc_idx = module.symbols.len();
                module.add_symbol(SymbolRecord::GlobalProc(Procedure {
                    parent: None,
                    end: 0.into(),
                    next: None,
                    code_size: func_size as u32,
                    dbg_start_offset: 0,
                    dbg_end_offset: 0,
                    function_type: void_fn_type,
                    code_offset: DataRegionOffset::new(func_offset, section_idx),
                    properties: ProcedureProperties::new(),
                    name: StrBuf::new(func_name.clone()),
                }));
                let end_idx = module.add_symbol(SymbolRecord::ProcEnd);
                match &mut module.symbols[proc_idx] {
                    SymbolRecord::GlobalProc(proc) => proc.end = end_idx,
                    _ => unreachable!(),
                }

                // add to publics table
                builder.dbi().symbols().add(Public {
                    properties: PublicProperties::new().with_is_function(true),
                    offset: DataRegionOffset::new(func_offset, section_idx),
                    name: StrBuf::new(func_name),
                });
            }
        }

        builder.dbi().add_module(module);
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
