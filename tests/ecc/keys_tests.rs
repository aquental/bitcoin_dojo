#[cfg(test)]
mod tests {
    use bitcoin_dojo::ecc::curve::Point;
    use bitcoin_dojo::ecc::keys::{PrivateKey, PublicKey};
    use bitcoin_dojo::ecc::scalar::Scalar;
    use num_bigint::BigUint;

    #[test]
    fn test_private_key_new() {
        let private_key = PrivateKey::new();

        // Verify that the private key has a scalar
        assert!(private_key.scalar().value() > &BigUint::from(0u32));

        // Verify that multiple calls to new() generate different keys
        let private_key2 = PrivateKey::new();
        assert_ne!(private_key.scalar().value(), private_key2.scalar().value());
    }

    #[test]
    fn test_private_key_default() {
        let private_key1 = PrivateKey::new();
        let private_key2 = PrivateKey::default();

        // Both should create valid private keys (though they'll be different due to randomness)
        assert!(private_key1.scalar().value() > &BigUint::from(0u32));
        assert!(private_key2.scalar().value() > &BigUint::from(0u32));

        // They should be different since they're randomly generated
        assert_ne!(private_key1.scalar().value(), private_key2.scalar().value());
    }

    #[test]
    fn test_private_key_from_scalar() {
        let scalar_value = BigUint::from(12345u32);
        let scalar = Scalar::new(scalar_value.clone());
        let private_key = PrivateKey::from_scalar(scalar);

        assert_eq!(private_key.scalar().value(), &scalar_value);
    }

    #[test]
    fn test_public_key_generation() {
        let private_key = PrivateKey::new();
        let public_key: PublicKey = private_key.public_key();

        // Verify that the public key point is not the point at infinity
        assert!(public_key.point().x().is_some());
        assert!(public_key.point().y().is_some());
    }

    #[test]
    fn test_public_key_deterministic() {
        let scalar_value = BigUint::from(54321u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);

        let public_key1: PublicKey = private_key.public_key();
        let public_key2: PublicKey = private_key.public_key();

        // Same private key should always generate the same public key
        assert_eq!(public_key1, public_key2);
    }

    #[test]
    fn test_different_private_keys_generate_different_public_keys() {
        let scalar1 = Scalar::new(BigUint::from(111u32));
        let scalar2 = Scalar::new(BigUint::from(222u32));

        let private_key1 = PrivateKey::from_scalar(scalar1);
        let private_key2 = PrivateKey::from_scalar(scalar2);

        let public_key1: PublicKey = private_key1.public_key();
        let public_key2: PublicKey = private_key2.public_key();

        assert_ne!(public_key1, public_key2);
    }

    #[test]
    fn test_key_pair_consistency() {
        // Test that the public key is correctly derived from private key
        let scalar_value = BigUint::from(999u32);
        let scalar = Scalar::new(scalar_value);
        let private_key = PrivateKey::from_scalar(scalar);
        let public_key: PublicKey = private_key.public_key();

        // Manually compute what the public key should be
        let generator = Point::generator();
        let expected_point = generator.multiply(private_key.scalar());

        // The public key point should match our manual calculation
        assert!(public_key.point().same_point(&expected_point));
    }

    #[test]
    fn test_edge_case_scalar_one() {
        let scalar_one = Scalar::new(BigUint::from(1u32));
        let private_key = PrivateKey::from_scalar(scalar_one);
        let public_key: PublicKey = private_key.public_key();

        // Public key should be the generator point when private key is 1
        let generator = Point::generator();
        assert!(public_key.point().same_point(&generator));
    }
}
