use std::ops::Deref;
use ed25519_dalek::ed25519::signature::rand_core::{CryptoRng, Rng};
use rand::RngExt;

pub struct EphemeralSecret(x25519_dalek::StaticSecret, u8);

impl EphemeralSecret {
    pub fn ephemeral_from_rng<R: Rng + CryptoRng>(rng: &mut R) -> EphemeralSecret {
        let mut private = x25519_dalek::StaticSecret::random_from_rng(rng);
        let tweak: u8 = rng.random();

        while to_representative(&private, tweak).is_none() {
            private = x25519_dalek::StaticSecret::random_from_rng(rng);
        }

        EphemeralSecret(private, tweak)
    }

    pub fn representative(&self) -> [u8; 32] {
        to_representative(&self.0, self.1).unwrap()
    }
}

impl Deref for EphemeralSecret {
    type Target = x25519_dalek::StaticSecret;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

const MASK_UNSET_BYTE: u8 = 0x3f;
const MASK_SET_BYTE: u8 = 0xc0;

const DIVIDE_MINUS_P_1_2_BYTES: [u8; 32] = [
    0xf6, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x3f,
];

fn to_representative(point: &x25519_dalek::StaticSecret, tweak: u8) -> Option<[u8; 32]> {
    let pubkey = curve25519_dalek::EdwardsPoint::mul_base_clamped(point.to_bytes()).to_montgomery();
    let v_in_sqrt = v_in_sqrt(point.as_bytes());
    point_to_representative(&pubkey, v_in_sqrt).map(|mut a| {
        a[31] |= MASK_SET_BYTE & tweak;
        a
    })
}

pub fn from_representative(mut r: [u8; 32]) -> curve25519_dalek::EdwardsPoint {
    r[31] &= MASK_UNSET_BYTE;
    let representative = curve25519_dalek::field::FieldElement::from_bytes(&r);
    let (x, y) = map_fe_to_edwards(&representative);
    curve25519_dalek::EdwardsPoint {
        X: x,
        Y: y,
        Z: curve25519_dalek::field::FieldElement::ONE,
        T: &x * &y,
    }
}

fn v_in_sqrt(key_input: &[u8; 32]) -> bool {
    let mut masked_pk = *key_input;
    masked_pk[0] &= 0xf8;
    masked_pk[31] &= 0x7f;
    masked_pk[31] |= 0x40;
    let pubkey = curve25519_dalek::EdwardsPoint::mul_base_clamped(masked_pk);
    v_in_sqrt_pubkey_edwards(&pubkey)
}

fn v_in_sqrt_pubkey_edwards(pubkey: &curve25519_dalek::EdwardsPoint) -> bool {
    let divide_minus_p_1_2 = curve25519_dalek::field::FieldElement::from_bytes(&DIVIDE_MINUS_P_1_2_BYTES);
    let (_, sqrt_minus_a_plus_2) = curve25519_dalek::field::FieldElement::sqrt_ratio_i(
        &(&curve25519_dalek::constants::MONTGOMERY_A_NEG - &(&curve25519_dalek::field::FieldElement::ONE + &curve25519_dalek::field::FieldElement::ONE)),
        &curve25519_dalek::field::FieldElement::ONE,
    );
    let inv1 = (&(&pubkey.Z - &pubkey.Y) * &pubkey.X).invert();
    let t0 = &pubkey.Y + &pubkey.Z;
    let v = &(&t0 * &inv1) * &(&pubkey.Z * &sqrt_minus_a_plus_2);
    divide_minus_p_1_2.gt(&v).into()
}

fn point_to_representative(
    point: &curve25519_dalek::MontgomeryPoint,
    v_in_sqrt: bool,
) -> Option<[u8; 32]> {
    let divide_minus_p_1_2 = curve25519_dalek::field::FieldElement::from_bytes(&DIVIDE_MINUS_P_1_2_BYTES);
    let a = &curve25519_dalek::field::FieldElement::from_bytes(&point.0);
    let a_neg = -a;

    if !is_encodable(a) {
        return None;
    }

    let (_r1_sqrt, r1) = curve25519_dalek::field::FieldElement::sqrt_ratio_i(
        &a_neg,
        &(&(a + &curve25519_dalek::constants::MONTGOMERY_A) * &(&curve25519_dalek::field::FieldElement::ONE + &curve25519_dalek::field::FieldElement::ONE)),
    );
    let (_r0_sqrt, r0) = curve25519_dalek::field::FieldElement::sqrt_ratio_i(
        &(&a_neg - &curve25519_dalek::constants::MONTGOMERY_A),
        &(a * &(&curve25519_dalek::field::FieldElement::ONE + &curve25519_dalek::field::FieldElement::ONE)),
    );
    let mut b = if v_in_sqrt {
        r0
    } else {
        r1
    };
    if divide_minus_p_1_2.gt(&b).into() {
        b.negate();
    }
    Some(b.to_bytes())
}

#[inline]
fn is_encodable(u: &curve25519_dalek::field::FieldElement) -> bool {
    let b0 = u + &curve25519_dalek::constants::MONTGOMERY_A;
    let b1 = &(&(&b0.square().square() * &b0.square()) * &b0) * u;
    let c = b1.pow_p58();
    let b2 = &(&b0.square().square().square() * &b0.square().square()) * &b0.square();
    let mut chi = &(&c.square().square() * &u.square()) * &b2;
    chi = -&chi;
    let chi_bytes = chi.to_bytes();
    chi_bytes[1] == 0
}

#[inline]
fn high_y(d: &curve25519_dalek::field::FieldElement) -> bool {
    let d_sq = &d.square();
    let au = &curve25519_dalek::constants::MONTGOMERY_A * d;
    let inner = &(d_sq + &au) + &curve25519_dalek::field::FieldElement::ONE;
    let eps = d * &inner;
    let (eps_is_sq, _) = curve25519_dalek::field::FieldElement::sqrt_ratio_i(&eps, &curve25519_dalek::field::FieldElement::ONE);
    eps_is_sq.into()
}

fn map_to_curve_parts(
    r: &curve25519_dalek::field::FieldElement
) -> (curve25519_dalek::field::FieldElement, curve25519_dalek::field::FieldElement, curve25519_dalek::field::FieldElement, curve25519_dalek::field::FieldElement) {
    let zero = curve25519_dalek::field::FieldElement::ZERO;
    let one = curve25519_dalek::field::FieldElement::ONE;
    let minus_one = -&curve25519_dalek::field::FieldElement::ONE;
    let mut tv1 = r.square2();
    if tv1.eq(&minus_one) {
        tv1 = zero;
    }
    let d_1 = &one + &tv1;
    let d = &curve25519_dalek::constants::MONTGOMERY_A_NEG * &(d_1.invert());
    let inner = &(&d.square() + &(&d * &curve25519_dalek::constants::MONTGOMERY_A)) + &one;
    let gx1 = &d * &inner;
    let gx2 = &gx1 * &tv1;
    let eps_is_sq = high_y(&d);
    let a_temp = if eps_is_sq {
        zero
    } else {
        curve25519_dalek::constants::MONTGOMERY_A
    };
    let mut x = &d + &a_temp;
    if !eps_is_sq {
        x.negate();
    }

    // complete Y
    let y2 = if eps_is_sq {
        gx1
    } else {
        gx2
    };
    let (_, mut y) = curve25519_dalek::field::FieldElement::sqrt_ratio_i(&y2, &one);
    if eps_is_sq ^ Into::<bool>::into(y.is_negative()) {
        y.negate();
    }

    (&x * &d_1, d_1, y, one)
}

fn map_fe_to_edwards(r: &curve25519_dalek::field::FieldElement) -> (curve25519_dalek::field::FieldElement, curve25519_dalek::field::FieldElement) {
    let (xmn, xmd, ymn, ymd) = map_to_curve_parts(r);
    let c1 = &(&curve25519_dalek::constants::MONTGOMERY_A_NEG - &curve25519_dalek::field::FieldElement::ONE) - &curve25519_dalek::field::FieldElement::ONE;
    let (_, c1) = curve25519_dalek::field::FieldElement::sqrt_ratio_i(&c1, &curve25519_dalek::field::FieldElement::ONE);
    let mut xn = &(&xmn * &ymd) * &c1;
    let mut xd = &xmd * &ymn;
    let mut yn = &xmn - &xmd;
    let mut yd = &xmn + &xmd;
    if (&xd * &yd).is_zero().into() {
        xn = curve25519_dalek::field::FieldElement::ZERO;
        xd = curve25519_dalek::field::FieldElement::ONE;
        yn = curve25519_dalek::field::FieldElement::ONE;
        yd = curve25519_dalek::field::FieldElement::ONE;
    }
    (&xn * &(xd.invert()), &yn * &(yd.invert()))
}