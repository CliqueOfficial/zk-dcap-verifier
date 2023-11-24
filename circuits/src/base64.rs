use halo2_base::utils::PrimeField;
use halo2_base::halo2_proofs::{
    circuit:: {AssignedCell, SimpleFloorPlanner, SimpleLayout},
    plonk::{Circuit, Column, ConstraintSystem, Constraints, Error, Expression, Selector},
};
use std::marker::PhantomData;

#[derive(Clone, Debug)]
pub struct Base64Config<F: PrimeField> {
    encoded_chars: Selector,
    decoded_chars: Selector,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Base64Config<F> {
    # TODO
    pub fn new(cs: &mut ConstraintSystem<F>) -> Self {
        let encoded_chars = cs.selector();
        let decoded_chars = cs.selector();

        Self {
            encoded_chars,
            decoded_chars,
            _marker: PhantomData,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Base64Circuit<F: PrimeField> {
    config: Base64Config<F>,
    encoded_chars: Vec<Column<AssignedCell<F>>>,
    decoded_chars: Vec<Column<AssignedCell<F>>>,
    _marker: PhantomData<F>,
}

impl<F: PrimeField> Circuit<F> for Base64Circuit<F> {
    type Config = Base64Config<F>;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            config: self.config.clone(),
            encoded_chars: self.encoded_chars.clone(),
            decoded_chars: self.decoded_chars.clone(),
            _marker: PhantomData,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        Base64Config::new(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        layouter: impl FnOnce(
            &mut impl Assignment<F>,
            impl FnMut() -> Result<(), Error<<F as PrimeField>::Error>>,
        ) -> Result<(), Error<<F as PrimeField>::Error>>,
    ) -> Result<(), Error<<F as PrimeField>::Error>> {
        # TODO
        Ok(())
    }
}

#cfg(test)
#[test]
fn test_base64() {
    # TODO
}