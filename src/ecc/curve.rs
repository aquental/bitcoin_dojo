/// src/ecc/curve.rs
use crate::ecc::field::{FieldElement, Pow};
use crate::ecc::scalar::Scalar;
use num_bigint::BigUint;
use std::ops::{Add, Mul};

#[derive(Debug, Clone)]
pub struct Point {
    x: Option<FieldElement>,
    y: Option<FieldElement>,
    a: FieldElement,
    b: FieldElement,
}

impl Point {
    /// Creates a new point on the elliptic curve defined by coefficients `a` and `b`.
    ///
    /// If `x` and `y` are provided, checks that the point is on the curve.
    /// If `x` and `y` are not provided, returns a point at infinity.
    ///
    /// # Panics
    ///
    /// Panics if the point is not on the curve.
    pub fn new(
        x: Option<FieldElement>,
        y: Option<FieldElement>,
        a: FieldElement,
        b: FieldElement,
    ) -> Self {
        match (x, y) {
            (Some(x), Some(y)) => {
                let x_cubed = x.pow(BigUint::from(3u32));
                let ax = &a * &x;
                let right_side = &(&x_cubed + &ax) + &b;
                let y_squared = y.pow(BigUint::from(2u32));
                if y_squared != right_side {
                    panic!("({x:?}, {y:?}) is not on the curve")
                }
                Self {
                    x: Some(x),
                    y: Some(y),
                    a,
                    b,
                }
            }
            (None, None) => Self {
                x: None,
                y: None,
                a,
                b,
            },
            _ => {
                panic!("Invalid parameters to Point::new()")
            }
        }
    }

    /// Returns a reference to the x-coordinate of the point, if it exists.
    /// Otherwise, returns a reference to None.
    pub fn x(&self) -> &Option<FieldElement> {
        &self.x
    }

    /// Returns a reference to the y-coordinate of the point, if it exists.
    /// Otherwise, returns a reference to None.
    pub fn y(&self) -> &Option<FieldElement> {
        &self.y
    }

    /// Returns a reference to the coefficient `a` of the curve.
    pub fn a(&self) -> &FieldElement {
        &self.a
    }

    /// Returns a reference to the coefficient `b` of the curve.
    pub fn b(&self) -> &FieldElement {
        &self.b
    }

    /// Returns the point at infinity on the curve defined by coefficients `a` and `b`.
    pub fn infinity(a: FieldElement, b: FieldElement) -> Self {
        Self {
            x: None,
            y: None,
            a,
            b,
        }
    }

    /// Returns a new point at infinity with the same curve parameters as `self`.
    pub fn new_infinity(&self) -> Self {
        Self {
            x: None,
            y: None,
            a: self.a.clone(),
            b: self.b.clone(),
        }
    }

    /// Returns true if the point is the point at infinity, false otherwise.
    pub fn is_infinity(&self) -> bool {
        self.x.is_none() && self.y.is_none()
    }

    /// Multiply the point by a scalar.
    ///
    /// This function multiplies the point by a scalar, using the existing
    /// multiplication function with a BigUint.
    pub fn multiply(&self, scalar: &Scalar) -> Self {
        // Convert scalar to BigUint and use existing multiplication
        let coef = scalar.value().clone();
        self * coef
    }

    /// Checks if this point is the same as another (ignoring curve parameters).
    ///
    /// Returns true if the points are the same (ignoring curve parameters), false otherwise.
    ///
    /// # Examples
    ///
    ///
    pub fn same_point(&self, other: &Point) -> bool {
        match (&self.x, &other.x, &self.y, &other.y) {
            (Some(x1), Some(x2), Some(y1), Some(y2)) => x1 == x2 && y1 == y2,
            (None, None, None, None) => true,
            _ => false,
        }
    }
}

impl PartialEq for Point {
    /// Returns true if the points are the same (ignoring curve parameters), false otherwise.
    ///
    /// Two points are considered the same if they have the same x and y coordinates,
    /// and if they are on the same elliptic curve (i.e. they have the same coefficients `a` and `b`).
    fn eq(&self, other: &Self) -> bool {
        let x_eq = match (&self.x, &other.x) {
            (Some(x1), Some(x2)) => x1 == x2,
            (None, None) => true,
            _ => false,
        };
        let y_eq = match (&self.y, &other.y) {
            (Some(y1), Some(y2)) => y1 == y2,
            (None, None) => true,
            _ => false,
        };
        x_eq && y_eq && self.a == other.a && self.b == other.b
    }
}

impl Add for Point {
    type Output = Point;

    /// Returns the result of adding two points together.
    ///
    /// The points must be on the same elliptic curve, and the resulting point will also be on the same curve.
    ///
    /// If the points are the same, the result will be twice the point.
    ///
    /// If one of the points is the point at infinity, the result will be the other point.
    ///
    /// If the points are negatives of each other, the result will be the point at infinity.
    fn add(self, other: Point) -> Point {
        &self + &other
    }
}

impl Add<&Point> for Point {
    type Output = Point;

    /// Returns the result of adding two points together.
    ///
    /// The points must be on the same elliptic curve, and the resulting point will also be on the same curve.
    ///
    /// If the points are the same, the result will be twice the point.
    ///
    /// If one of the points is the point at infinity, the result will be the other point.
    ///
    /// If the points are negatives of each other, the result will be the point at infinity.
    fn add(self, other: &Point) -> Point {
        &self + other
    }
}

impl Add<Point> for &Point {
    type Output = Point;

    /// Returns the result of adding two points together.
    ///
    /// The points must be on the same elliptic curve, and the resulting point will also be on the same curve.
    ///
    /// If the points are the same, the result will be twice the point.
    ///
    /// If one of the points is the point at infinity, the result will be the other point.
    ///
    /// If the points are negatives of each other, the result will be the point at infinity.
    fn add(self, other: Point) -> Point {
        self + &other
    }
}

impl Add for &Point {
    type Output = Point;

    /// Returns the result of adding two points together.
    ///
    /// The points must be on the same elliptic curve, and the resulting point will also be on the same curve.
    ///
    /// If the points are the same, the result will be twice the point.
    ///
    /// If one of the points is the point at infinity, the result will be the other point.
    ///
    /// If the points are negatives of each other, the result will be the point at infinity.
    fn add(self, other: Self) -> Point {
        if (self.a != other.a) | (self.b != other.b) {
            panic!("Points {self:?}, {other:?} are not on the same curve.");
        }

        if self.x.is_none() {
            // self is point at infinity
            return other.clone();
        }

        if other.x.is_none() {
            // other is point at infinity
            return self.clone();
        }

        let x1 = self.x.as_ref().unwrap();
        let y1 = self.y.as_ref().unwrap();
        let x2 = other.x.as_ref().unwrap();
        let y2 = other.y.as_ref().unwrap();

        // Case: Points have same x but different y (vertical line, points are negatives)
        if x1 == x2 && y1 != y2 {
            return self.new_infinity();
        }

        // Case: Points are the same (point doubling)
        if self.same_point(other) {
            // Sub case: y-coordinate is zero, tangent is vertical
            if y1.is_zero() {
                return self.new_infinity();
            }

            // Point doubling: s = (3x1**2 + a) / (2y1)
            let three = FieldElement::new(BigUint::from(3u32), x1.prime().clone());
            let two = FieldElement::new(BigUint::from(2u32), x1.prime().clone());
            let x1_squared = x1.pow(BigUint::from(2u32));
            let numerator = &(&three * &x1_squared) + &self.a;
            let denominator = &two * y1;
            let s = &numerator / &denominator;

            // x3 = s**2 - 2x1
            let s_squared = s.pow(BigUint::from(2u32));
            let two_x1 = &two * x1;
            let x3 = &s_squared - &two_x1;

            // y3 = s(x1 - x3) - y1
            let x1_minus_x3 = x1 - &x3;
            let y3 = &(&s * &x1_minus_x3) - y1;

            return Point::new(Some(x3), Some(y3), self.a.clone(), self.b.clone());
        }

        // Case: P1 != P2
        // s = (y2 - y1) / (x2 - x1)
        let numerator = y2 - y1;
        let denominator = x2 - x1;
        let s = &numerator / &denominator;

        // x3 = s**2 - x1 - x2
        let s_squared = s.pow(BigUint::from(2u32));
        let x3 = &(&s_squared - x1) - x2;

        // y3 = s(x1 - x3) - y1
        let x1_minus_x3 = x1 - &x3;
        let y3 = &(&s * &x1_minus_x3) - y1;

        Point::new(Some(x3), Some(y3), self.a.clone(), self.b.clone())
    }
}

impl Mul<BigUint> for Point {
    type Output = Point;

    /// Scalar multiplication using a BigUint coefficient.
    ///
    /// Returns a new point which is the result of multiplying the current point by the given coefficient.
    ///
    /// # Examples
    ///
    ///
    /// let p = Point::new(x, y, a, b);
    /// let c = BigUint::from(2u32);
    /// let result = p * c;
    /// assert_eq!(result.x, x * x * c.mod_pow(&BigUint::from(2u32).pow(3 as u32)));
    /// assert_eq!(result.y, (x * (a * c.mod_pow(&BigUint::from(2u32).pow(3 as u32) + b * c.mod_pow(&BigUint::from(2u32).pow(2 as u32))) % (p.a * c.mod_pow(&BigUint::from(2u32).pow(3 as u32) + p.b * c.mod_pow(&BigUint::from(2u32).pow(2 as u32)));
    fn mul(self, coefficient: BigUint) -> Self::Output {
        &self * coefficient
    }
}

impl Mul<&BigUint> for Point {
    type Output = Point;

    /// Scalar multiplication using a reference to a BigUint coefficient.
    ///
    /// Returns a new point which is the result of multiplying the current point by the given coefficient.
    ///
    /// # Examples
    ///
    ///
    /// let p = Point::new(x, y, a, b);
    /// let c = BigUint::from(2u32);
    /// let result = p * &c;
    /// assert_eq!(result.x, x * x * c.mod_pow(&BigUint::from(2u32).pow(3 as u32)));
    /// assert_eq!(result.y, (x * (a * c.mod_pow(&BigUint::from(2u32).pow(3 as u32) + b * c.mod_pow(&BigUint::from(2u32).pow(2 as u32))) % (p.a * c.mod_pow(&BigUint::from(2u32).pow(3 as u32) + p.b * c.mod_pow(&BigUint::from(2u32).pow(2 as u32)));
    fn mul(self, coefficient: &BigUint) -> Self::Output {
        &self * coefficient.clone()
    }
}

impl Mul<BigUint> for &Point {
    type Output = Point;

    // Scalar multiplication using binary expansion
    fn mul(self, coefficient: BigUint) -> Self::Output {
        let mut coef = coefficient;
        let mut current = self.clone();
        let mut result = self.new_infinity();

        while coef > BigUint::from(0u32) {
            // Check if the rightmost bit is 1
            if &coef & BigUint::from(1u32) == BigUint::from(1u32) {
                result = &result + &current;
            }
            // Double the current point
            current = &current + &current;
            // Right shift the coefficient
            coef >>= 1;
        }
        result
    }
}

impl Mul<&BigUint> for &Point {
    type Output = Point;

    /// Scalar multiplication using a reference to a BigUint coefficient.
    ///
    /// Returns a new point which is the result of multiplying the current point by the given coefficient.
    ///
    /// # Examples
    ///
    ///
    /// let p = Point::new(x, y, a, b);
    /// let c = BigUint::from(2u32);
    /// let result = p * &c;
    /// assert_eq!(result.x, x * x * c.mod_pow(&BigUint::from(2u32).pow(3 as u32)));
    /// assert_eq!(result.y, (x * (a * c.mod_pow(&BigUint::from(2u32).pow(3 as u32) + b * c.mod_pow(&BigUint::from(2u32).pow(2 as u32))) % (p.a * c.mod_pow(&BigUint::from(2u32).pow(3 as u32) + p.b * c.mod_pow(&BigUint::from(2u32).pow(2 as u32)));
    fn mul(self, coefficient: &BigUint) -> Self::Output {
        self * coefficient.clone()
    }
}

// Implement scalar multiplication with Scalar type
impl Mul<Scalar> for Point {
    type Output = Point;

    /// Returns a new point which is the result of multiplying the current point by the given scalar.
    ///
    /// # Examples
    ///
    /// let p = Point::new(x, y, a, b);
    /// let c = Scalar::new(BigUint::from(2u32));
    /// let result = p * c;
    /// assert_eq!(result.x, x * x * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32)));
    /// assert_eq!(result.y, (x * (a * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32) + b * c.value().mod_pow(&BigUint::from(2u32).pow(2 as u32))) % (p.a * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32) + p.b * c.value().mod_pow(&BigUint::from(2u32).pow(2 as u32)));
    fn mul(self, scalar: Scalar) -> Self::Output {
        &self * scalar.value().clone()
    }
}

impl Mul<&Scalar> for Point {
    type Output = Point;

    /// Returns a new point which is the result of multiplying the current point by the given scalar.
    ///
    /// # Examples
    ///
    ///
    /// let p = Point::new(x, y, a, b);
    /// let c = Scalar::new(BigUint::from(2u32));
    /// let result = &p * &c;
    /// assert_eq!(result.x, x * x * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32)));
    /// assert_eq!(result.y, (x * (a * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32) + b * c.value().mod_pow(&BigUint::from(2u32).pow(2 as u32))) % (p.a * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32) + p.b * c.value().mod_pow(&BigUint::from(2u32).pow(2 as u32)));
    fn mul(self, scalar: &Scalar) -> Self::Output {
        &self * scalar.value().clone()
    }
}

impl Mul<Scalar> for &Point {
    type Output = Point;

    /// Returns a new point which is the result of multiplying the current point by the given scalar.
    ///
    /// # Examples
    ///
    ///
    /// let p = Point::new(x, y, a, b);
    /// let c = Scalar::new(BigUint::from(2u32));
    /// let result = &p * c;
    /// assert_eq!(result.x, x * x * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32)));
    /// assert_eq!(result.y, (x * (a * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32) + b * c.value().mod_pow(&BigUint::from(2u32).pow(2 as u32))) % (p.a * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32) + p.b * c.value().mod_pow(&BigUint::from(2u32).pow(2 as u32)));
    fn mul(self, scalar: Scalar) -> Self::Output {
        self * scalar.value().clone()
    }
}

impl Mul<&Scalar> for &Point {
    type Output = Point;

    /// Returns a new point which is the result of multiplying the current point by the given scalar.
    ///
    /// # Examples
    ///
    /// let p = Point::new(x, y, a, b);
    /// let c = Scalar::new(BigUint::from(2u32));
    /// let result = &p * &c;
    /// assert_eq!(result.x, x * x * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32)));
    /// assert_eq!(result.y, (x * (a * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32) + b * c.value().mod_pow(&BigUint::from(2u32).pow(2 as u32))) % (p.a * c.value().mod_pow(&BigUint::from(2u32).pow(3 as u32) + p.b * c.value().mod_pow(&BigUint::from(2u32).pow(2 as u32)));
    fn mul(self, scalar: &Scalar) -> Self::Output {
        self * scalar.value().clone()
    }
}
