/**
 * secp256k1 curve parameters (SECG SEC 2 v2, §2.4.1)
 */
export declare namespace Curve {
    /** Field prime p */
    const P = 115792089237316195423570985008687907853269984665640564039457584007908834671663n;
    /** Curve order n (number of points) */
    const N = 115792089237316195423570985008687907852837564279074904382605163141518161494337n;
    /** Coefficient a = 0 */
    const A = 0n;
    /** Coefficient b = 7 */
    const B = 7n;
    /** Generator point Gx */
    const Gx = 55066263022277343669578718895168534326250603453777594175500187360389116729240n;
    /** Generator point Gy */
    const Gy = 32670510020758816978083085130507043184471273380659243275938904335757337482424n;
    /** Half of N, used for low-S normalisation */
    const HALF_N: bigint;
}
/** a mod m, always non-negative */
export declare function mod(a: bigint, m: bigint): bigint;
/** Modular inverse via extended Euclidean algorithm */
export declare function modInv(a: bigint, m: bigint): bigint;
/** Fast modular exponentiation */
export declare function modPow(base: bigint, exp: bigint, m: bigint): bigint;
/** Modular square root (p ≡ 3 mod 4 so Tonelli-Shanks is simple) */
export declare function modSqrt(n: bigint, p: bigint): bigint;
/** Jacobian coordinates (X : Y : Z) where affine = (X/Z², Y/Z³) */
export declare class JacobianPoint {
    readonly x: bigint;
    readonly y: bigint;
    readonly z: bigint;
    constructor(x: bigint, y: bigint, z: bigint);
    static readonly ZERO: JacobianPoint;
    static readonly G: JacobianPoint;
    get isZero(): boolean;
    /** Convert to affine (x, y) */
    toAffine(): {
        x: bigint;
        y: bigint;
    };
    negate(): JacobianPoint;
    double(): JacobianPoint;
    add(other: JacobianPoint): JacobianPoint;
    /** Double-and-add scalar multiplication */
    mul(scalar: bigint): JacobianPoint;
}
//# sourceMappingURL=curve.d.ts.map