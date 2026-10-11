package crypto

import (
	"errors"
	"math/big"
	"slices"
)

// The arithmetic below works on public values only (key validation and
// conversion), so math/big, which is not constant time, is acceptable here.
// Signatures are verified by crypto/ed25519.

// edwards holds the constants of edwards25519 (RFC 8032 §5.1).
type edwards struct {
	p, d, sqrtM1, expSqrt *big.Int
}

func newEdwards() edwards {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// d = -121665/121666 mod p
	d := new(big.Int).ModInverse(big.NewInt(121666), p)
	d.Mul(d, big.NewInt(-121665)).Mod(d, p)
	// sqrt(-1) = 2^((p-1)/4) mod p
	e := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 2)
	sqrtM1 := new(big.Int).Exp(big.NewInt(2), e, p)
	// (p-5)/8, the exponent of the square root candidate
	expSqrt := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(5)), 3)
	return edwards{p: p, d: d, sqrtM1: sqrtM1, expSqrt: expSqrt}
}

// edPoint is an affine point of edwards25519.
type edPoint struct{ x, y *big.Int }

var (
	errNonCanonical = errors.New("not a canonical point encoding")
	errNotOnCurve   = errors.New("not a point on the curve")
	errSmallOrder   = errors.New("point of small order")
)

// littleEndian returns the integer of a little-endian byte string.
func littleEndian(b []byte) *big.Int {
	be := slices.Clone(b)
	slices.Reverse(be)
	return new(big.Int).SetBytes(be)
}

// decode decodes a 32-byte point encoding following RFC 8032 §5.1.3, and in
// addition rejects a y coordinate that is not reduced modulo p.
func (c edwards) decode(enc []byte) (edPoint, error) {
	b := slices.Clone(enc)
	sign := uint(b[31] >> 7)
	b[31] &= 0x7f
	y := littleEndian(b)
	if y.Cmp(c.p) >= 0 {
		return edPoint{}, errNonCanonical
	}
	y2 := new(big.Int).Mul(y, y)
	u := new(big.Int).Sub(y2, big.NewInt(1))
	u.Mod(u, c.p)
	v := new(big.Int).Mul(c.d, y2)
	v.Add(v, big.NewInt(1)).Mod(v, c.p)
	// x = u v^3 (u v^7)^((p-5)/8)
	v3 := new(big.Int).Exp(v, big.NewInt(3), c.p)
	v7 := new(big.Int).Exp(v, big.NewInt(7), c.p)
	t := new(big.Int).Mul(u, v7)
	t.Exp(t.Mod(t, c.p), c.expSqrt, c.p)
	x := new(big.Int).Mul(u, v3)
	x.Mul(x, t).Mod(x, c.p)
	vx2 := new(big.Int).Mul(x, x)
	vx2.Mul(vx2, v).Mod(vx2, c.p)
	negU := new(big.Int).Sub(c.p, u)
	negU.Mod(negU, c.p)
	switch {
	case vx2.Cmp(u) == 0:
	case vx2.Cmp(negU) == 0:
		x.Mul(x, c.sqrtM1).Mod(x, c.p)
	default:
		return edPoint{}, errNotOnCurve
	}
	if x.Sign() == 0 && sign == 1 {
		return edPoint{}, errNonCanonical
	}
	if x.Bit(0) != sign {
		x.Sub(c.p, x)
	}
	return edPoint{x: x, y: y}, nil
}

// add adds two points with the complete twisted Edwards addition law for
// a = -1 (RFC 8032 §5.1.4, affine form).
func (c edwards) add(a, b edPoint) edPoint {
	x1y2 := new(big.Int).Mul(a.x, b.y)
	y1x2 := new(big.Int).Mul(a.y, b.x)
	y1y2 := new(big.Int).Mul(a.y, b.y)
	x1x2 := new(big.Int).Mul(a.x, b.x)
	dxy := new(big.Int).Mul(c.d, x1x2)
	dxy.Mul(dxy, y1y2).Mod(dxy, c.p)
	one := big.NewInt(1)
	denX := new(big.Int).Add(one, dxy)
	denY := new(big.Int).Sub(one, dxy)
	x := new(big.Int).Add(x1y2, y1x2)
	x.Mul(x, denX.ModInverse(denX.Mod(denX, c.p), c.p)).Mod(x, c.p)
	y := new(big.Int).Add(y1y2, x1x2)
	y.Mul(y, denY.ModInverse(denY.Mod(denY, c.p), c.p)).Mod(y, c.p)
	return edPoint{x: x, y: y}
}

// smallOrder reports whether [8]P is the neutral element (0, 1), that is,
// whether P lies in the torsion subgroup of order dividing 8.
func (c edwards) smallOrder(pt edPoint) bool {
	q := pt
	for range 3 {
		q = c.add(q, q)
	}
	return q.x.Sign() == 0 && q.y.Cmp(big.NewInt(1)) == 0
}

// checkEdwardsPoint accepts a canonical encoding of a point that is not of
// small order.
func checkEdwardsPoint(enc []byte) error {
	c := newEdwards()
	pt, err := c.decode(enc)
	if err != nil {
		return err
	}
	if c.smallOrder(pt) {
		return errSmallOrder
	}
	return nil
}

// montgomeryU maps the Edwards y coordinate of a valid Ed25519 public key to
// the u coordinate of the birationally equivalent Curve25519 point,
// u = (1 + y) / (1 - y) (RFC 7748 §4.1), and returns it as 32 little-endian
// bytes (RFC 7748 §5).
func montgomeryU(enc []byte) ([]byte, error) {
	c := newEdwards()
	pt, err := c.decode(enc)
	if err != nil {
		return nil, err
	}
	if c.smallOrder(pt) {
		return nil, errSmallOrder
	}
	one := big.NewInt(1)
	num := new(big.Int).Add(one, pt.y)
	den := new(big.Int).Sub(one, pt.y)
	den.Mod(den, c.p)
	u := num.Mul(num, den.ModInverse(den, c.p)).Mod(num, c.p)
	out := make([]byte, 32)
	u.FillBytes(out)
	slices.Reverse(out)
	return out, nil
}
