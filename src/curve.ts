// deno-lint-ignore-file no-namespace

/**
 * secp256k1 curve parameters (SECG SEC 2 v2, §2.4.1)
 */
export namespace Curve {
  /** Field prime p */
  export const P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn

  /** Curve order n (number of points) */
  export const N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141n

  /** Coefficient a = 0 */
  export const A = 0n

  /** Coefficient b = 7 */
  export const B = 7n

  /** Generator point Gx */
  export const Gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798n

  /** Generator point Gy */
  export const Gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n

  /** Half of N, used for low-S normalisation */
  export const HALF_N = N >> 1n
}

// ─── Modular arithmetic ──────────────────────────────────────────────────────

/** a mod m, always non-negative */
export function mod(a: bigint, m: bigint): bigint {
  const r = a % m
  return r < 0n ? r + m : r
}

/** Modular inverse via extended Euclidean algorithm */
export function modInv(a: bigint, m: bigint): bigint {
  if (a === 0n) throw new Error("modInv: zero has no inverse")
  let [old_r, r] = [mod(a, m), m]
  let [old_s, s] = [1n, 0n]
  while (r !== 0n) {
    const q = old_r / r;
    [old_r, r] = [r, old_r - q * r];
    [old_s, s] = [s, old_s - q * s]
  }
  return mod(old_s, m)
}

/** Fast modular exponentiation */
export function modPow(base: bigint, exp: bigint, m: bigint): bigint {
  let result = 1n
  base = mod(base, m)
  while (exp > 0n) {
    if (exp & 1n) result = mod(result * base, m)
    base = mod(base * base, m)
    exp >>= 1n
  }
  return result
}

/** Modular square root (p ≡ 3 mod 4 so Tonelli-Shanks is simple) */
export function modSqrt(n: bigint, p: bigint): bigint {
  const r = modPow(n, (p + 1n) / 4n, p)
  if (mod(r * r, p) !== mod(n, p)) throw new Error("modSqrt: not a quadratic residue")
  return r
}

// ─── Projective (Jacobian) point ─────────────────────────────────────────────

/** Jacobian coordinates (X : Y : Z) where affine = (X/Z², Y/Z³) */
export class JacobianPoint {
  constructor(
    readonly x: bigint,
    readonly y: bigint,
    readonly z: bigint,
  ) {}

  static readonly ZERO = new JacobianPoint(0n, 1n, 0n)
  static readonly G    = new JacobianPoint(Curve.Gx, Curve.Gy, 1n)

  get isZero(): boolean {
    return this.z === 0n
  }

  /** Convert to affine (x, y) */
  toAffine(): { x: bigint; y: bigint } {
    if (this.isZero) throw new Error("Point at infinity has no affine representation")
    const { P } = Curve
    const zinv  = modInv(this.z, P)
    const zinv2 = mod(zinv * zinv, P)
    const zinv3 = mod(zinv2 * zinv, P)
    return {
      x: mod(this.x * zinv2, P),
      y: mod(this.y * zinv3, P),
    }
  }

  negate(): JacobianPoint {
    return new JacobianPoint(this.x, mod(-this.y, Curve.P), this.z)
  }

  double(): JacobianPoint {
    if (this.isZero) return this
    const { P } = Curve
    const { x: X1, y: Y1, z: Z1 } = this
    const A  = mod(Y1 * Y1, P)
    const B  = mod(4n * X1 * A, P)
    const C  = mod(3n * X1 * X1, P)           // a = 0 so no a·Z1⁴ term
    const D  = mod(C * C - 2n * B, P)
    const X3 = mod(D, P)
    const Y3 = mod(C * (B - D) - 8n * A * A, P)
    const Z3 = mod(2n * Y1 * Z1, P)
    return new JacobianPoint(X3, Y3, Z3)
  }

  add(other: JacobianPoint): JacobianPoint {
    if (this.isZero)  return other
    if (other.isZero) return this
    const { P } = Curve
    const { x: X1, y: Y1, z: Z1 } = this
    const { x: X2, y: Y2, z: Z2 } = other
    const Z1Z1 = mod(Z1 * Z1, P)
    const Z2Z2 = mod(Z2 * Z2, P)
    const U1   = mod(X1 * Z2Z2, P)
    const U2   = mod(X2 * Z1Z1, P)
    const S1   = mod(Y1 * Z2 * Z2Z2, P)
    const S2   = mod(Y2 * Z1 * Z1Z1, P)
    const H    = mod(U2 - U1, P)
    const R    = mod(S2 - S1, P)
    if (H === 0n) return R === 0n ? this.double() : JacobianPoint.ZERO
    const HH   = mod(H * H, P)
    const HHH  = mod(H * HH, P)
    const X3   = mod(R * R - HHH - 2n * U1 * HH, P)
    const Y3   = mod(R * (U1 * HH - X3) - S1 * HHH, P)
    const Z3   = mod(H * Z1 * Z2, P)
    return new JacobianPoint(X3, Y3, Z3)
  }

  /** Double-and-add scalar multiplication */
  mul(scalar: bigint): JacobianPoint {
    scalar = mod(scalar, Curve.N)
    if (scalar === 0n) return JacobianPoint.ZERO
    let result = JacobianPoint.ZERO
    let addend: JacobianPoint = this
    let k = scalar
    while (k > 0n) {
      if (k & 1n) result = result.add(addend)
      addend = addend.double()
      k >>= 1n
    }
    return result
  }
}
