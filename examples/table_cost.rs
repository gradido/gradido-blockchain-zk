//! How long the runtime search for the fixed base tables takes (orchard ships them as constants).
use std::time::Instant;
use halo2_gadgets::ecc::chip::{find_zs_and_us, NUM_WINDOWS, NUM_WINDOWS_SHORT};
use pasta_curves::pallas;
use group::{Curve, Group};

fn main() {
    let g = pallas::Point::generator().to_affine();
    let t = Instant::now();
    let _ = find_zs_and_us(g, NUM_WINDOWS).unwrap();
    println!("find_zs_and_us, full width ({NUM_WINDOWS} windows): {:?}", t.elapsed());
    let t = Instant::now();
    let _ = find_zs_and_us(g, NUM_WINDOWS_SHORT).unwrap();
    println!("find_zs_and_us, short ({NUM_WINDOWS_SHORT} windows):  {:?}", t.elapsed());
}
