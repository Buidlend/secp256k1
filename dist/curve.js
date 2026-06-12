// deno-lint-ignore-file no-namespace
/**
 * secp256k1 curve parameters (SECG SEC 2 v2, §2.4.1)
 */
export var Curve;
(function (Curve) {
    /** Field prime p */
    Curve.P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
    /** Curve order n (number of points) */
    Curve.N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
    /** Coefficient a = 0 */
    Curve.A = 0n;
    /** Coefficient b = 7 */
    Curve.B = 7n;
    /** Generator point Gx */
    Curve.Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
    /** Generator point Gy */
    Curve.Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;
    /** Half of N, used for low-S normalisation */
    Curve.HALF_N = Curve.N >> 1n;
})(Curve || (Curve = {}));
// ─── Modular arithmetic ──────────────────────────────────────────────────────
/** a mod m, always non-negative */
export function mod(a, m) {
    const r = a % m;
    return r < 0n ? r + m : r;
}
/** Modular inverse via extended Euclidean algorithm */
export function modInv(a, m) {
    if (a === 0n)
        throw new Error("modInv: zero has no inverse");
    let [old_r, r] = [mod(a, m), m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
        const q = old_r / r;
        [old_r, r] = [r, old_r - q * r];
        [old_s, s] = [s, old_s - q * s];
    }
    return mod(old_s, m);
}
/** Fast modular exponentiation */
export function modPow(base, exp, m) {
    let result = 1n;
    base = mod(base, m);
    while (exp > 0n) {
        if (exp & 1n)
            result = mod(result * base, m);
        base = mod(base * base, m);
        exp >>= 1n;
    }
    return result;
}
/** Modular square root (p ≡ 3 mod 4 so Tonelli-Shanks is simple) */
export function modSqrt(n, p) {
    const r = modPow(n, (p + 1n) / 4n, p);
    if (mod(r * r, p) !== mod(n, p))
        throw new Error("modSqrt: not a quadratic residue");
    return r;
}
// ─── Projective (Jacobian) point ─────────────────────────────────────────────
/** Jacobian coordinates (X : Y : Z) where affine = (X/Z², Y/Z³) */
export class JacobianPoint {
    x;
    y;
    z;
    constructor(x, y, z) {
        this.x = x;
        this.y = y;
        this.z = z;
    }
    static ZERO = new JacobianPoint(0n, 1n, 0n);
    static G = new JacobianPoint(Curve.Gx, Curve.Gy, 1n);
    get isZero() {
        return this.z === 0n;
    }
    /** Convert to affine (x, y) */
    toAffine() {
        if (this.isZero)
            throw new Error("Point at infinity has no affine representation");
        const { P } = Curve;
        const zinv = modInv(this.z, P);
        const zinv2 = mod(zinv * zinv, P);
        const zinv3 = mod(zinv2 * zinv, P);
        return {
            x: mod(this.x * zinv2, P),
            y: mod(this.y * zinv3, P),
        };
    }
    negate() {
        return new JacobianPoint(this.x, mod(-this.y, Curve.P), this.z);
    }
    double() {
        if (this.isZero)
            return this;
        const { P } = Curve;
        const { x: X1, y: Y1, z: Z1 } = this;
        const A = mod(Y1 * Y1, P);
        const B = mod(4n * X1 * A, P);
        const C = mod(3n * X1 * X1, P); // a = 0 so no a·Z1⁴ term
        const D = mod(C * C - 2n * B, P);
        const X3 = mod(D, P);
        const Y3 = mod(C * (B - D) - 8n * A * A, P);
        const Z3 = mod(2n * Y1 * Z1, P);
        return new JacobianPoint(X3, Y3, Z3);
    }
    add(other) {
        if (this.isZero)
            return other;
        if (other.isZero)
            return this;
        const { P } = Curve;
        const { x: X1, y: Y1, z: Z1 } = this;
        const { x: X2, y: Y2, z: Z2 } = other;
        const Z1Z1 = mod(Z1 * Z1, P);
        const Z2Z2 = mod(Z2 * Z2, P);
        const U1 = mod(X1 * Z2Z2, P);
        const U2 = mod(X2 * Z1Z1, P);
        const S1 = mod(Y1 * Z2 * Z2Z2, P);
        const S2 = mod(Y2 * Z1 * Z1Z1, P);
        const H = mod(U2 - U1, P);
        const R = mod(S2 - S1, P);
        if (H === 0n)
            return R === 0n ? this.double() : JacobianPoint.ZERO;
        const HH = mod(H * H, P);
        const HHH = mod(H * HH, P);
        const X3 = mod(R * R - HHH - 2n * U1 * HH, P);
        const Y3 = mod(R * (U1 * HH - X3) - S1 * HHH, P);
        const Z3 = mod(H * Z1 * Z2, P);
        return new JacobianPoint(X3, Y3, Z3);
    }
    /** Double-and-add scalar multiplication */
    mul(scalar) {
        scalar = mod(scalar, Curve.N);
        if (scalar === 0n)
            return JacobianPoint.ZERO;
        let result = JacobianPoint.ZERO;
        let addend = this;
        let k = scalar;
        while (k > 0n) {
            if (k & 1n)
                result = result.add(addend);
            addend = addend.double();
            k >>= 1n;
        }
        return result;
    }
}
//# sourceMappingURL=curve.js.map