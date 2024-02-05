use halo2_base::halo2_proofs::{
    circuit::{Layouter, Value},
    plonk::{ConstraintSystem, Error, TableColumn},
};
use halo2_base::utils::PrimeField;


use std::marker::PhantomData;


pub const BIT_COLUMN_COUNT: u8 = 4;

/// A lookup table of values from 0..RANGE.
#[derive(Debug, Clone, Copy)]
pub(super) struct BitDecompositionTableConfig<F: PrimeField> {
    pub(super) character: TableColumn, // This is the pre-mapped 6 bit character in ASCII (i.e. a-z, A-Z, 0-9, +, /)
    pub(super) value_encoded: TableColumn, // This is the 6 bit value that each of the above character maps to from 0-64
    pub(super) value_decoded: TableColumn, // This is the 8 bit value that you get after decoding the base64 values
    pub(super) bit_decompositions: [TableColumn; BIT_COLUMN_COUNT as usize],
    _marker: PhantomData<F>,
}

impl<F: PrimeField> BitDecompositionTableConfig<F> {
    pub(super) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let character = meta.lookup_table_column();
        let value_encoded = meta.lookup_table_column();
        let value_decoded = meta.lookup_table_column();
        let mut bit_decompositions = vec![];
        for _i in 0..BIT_COLUMN_COUNT {
            bit_decompositions.push(meta.lookup_table_column());
        }

        Self {
            character,
            value_encoded,
            value_decoded,
            bit_decompositions: bit_decompositions.try_into().unwrap(),
            _marker: PhantomData,
        }
    }

    pub(super) fn map_encoded_value_to_character(&self, value_encoded: u8) -> char {
        match value_encoded {
            0..=25 => (value_encoded + 65) as char,
            26..=51 => (value_encoded + 71) as char,
            52..=61 => (value_encoded - 4) as char,
            62 => '+',
            63 => '/',
            _ => panic!("Invalid value_encoded value"),
        }
    }

    pub(super) fn map_character_to_encoded_value(&self, character: char) -> u8 {
        match character {
            '=' => 0,
            'A'..='Z' => character as u8 - 65,
            'a'..='z' => character as u8 - 71,
            '0'..='9' => character as u8 + 4,
            '+' => 62,
            '/' => 63,
            _ => panic!("Invalid character"),
        }
    }

    pub(super) fn load(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        const OFFSET: usize = 1; // How many special characters we add into rows at the top (just = as 0)

        layouter.assign_table(
            || "load 64 bit table",
            |mut table| {
                // Assign ASCII characters and corresponding value_encoded values
                // Special case = to be 0
                table.assign_cell(
                    || "value_encoded",
                    self.value_encoded,
                    0,
                    || Value::known(F::from_u128(0_u128)),
                )?;
                // Assign each character value that corresponds to its base64 encoded value
                const equal: char = '=';
                table.assign_cell(
                    || "character",
                    self.character,
                    0,
                    || Value::known(F::from_u128(equal as u128)),
                )?;

                for value_encoded in 0..64 {
                    table.assign_cell(
                        || "value_encoded",
                        self.value_encoded,
                        value_encoded + OFFSET,
                        || Value::known(F::from_u128(value_encoded as u128)),
                    )?;
                    // Assign each character value that corresponds to its base64 encoded value
                    let character_var = self.map_encoded_value_to_character(value_encoded as u8);
                    table.assign_cell(
                        || "character",
                        self.character,
                        value_encoded + OFFSET,
                        || Value::known(F::from_u128(character_var as u128)),
                    )?;
                }

                Ok(())
            },
        )?;
        layouter.assign_table(
            || "load 256 bit table",
            |mut table| {
                // Special case = to be 0 at the top row
                for col in 0..BIT_COLUMN_COUNT {
                    table.assign_cell(
                        || "bit decompositions",
                        self.bit_decompositions[col as usize],
                        0,
                        || Value::known(F::from_u128(((0 >> (col * 2)) % 4) as u128)),
                    )?;
                }

                table.assign_cell(
                    || "value_decoded",
                    self.value_decoded,
                    0,
                    || Value::known(F::from_u128(0_u128)),
                )?;

                // Assign bit decompositions for each value_encoded and value_decoded value
                for i in 0..256 {
                    for col in 0..BIT_COLUMN_COUNT {
                        table.assign_cell(
                            || "bit decompositions",
                            self.bit_decompositions[col as usize],
                            i + OFFSET,
                            || Value::known(F::from_u128(((i >> (col * 2)) % 4) as u128)),
                        )?;
                    }
                    // Assign each value_decoded value
                    table.assign_cell(
                        || "value_decoded",
                        self.value_decoded,
                        i + OFFSET,
                        || Value::known(F::from_u128(i as u128)),
                    )?;
                }
                Ok(())
            },
        )
    }
}
