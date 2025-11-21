from __future__ import annotations
from dataclasses import dataclass
from typing import TypeVar, Self, TYPE_CHECKING, Generic

if TYPE_CHECKING:
    from .te_curve import TECurve
    from .te_affine_point import TEAffinePoint

C = TypeVar("C", bound="TECurve")

@dataclass(slots=True)
class TEProjectivePoint(Generic[C]):
    """
    Twisted Edwards Curve Point in Extended Projective Coordinates (X:Y:Z:T).
    x = X/Z, y = Y/Z, xy = T/Z
    """
    x: int
    y: int
    z: int
    t: int
    curve: C

    @classmethod
    def from_affine(cls, point: "TEAffinePoint") -> Self:
        return cls(
            point.x, 
            point.y, 
            1, 
            (point.x * point.y) % point.curve.PRIME_FIELD, 
            point.curve
        )

    def to_affine(self) -> "TEAffinePoint":
        from .te_affine_point import TEAffinePoint
        if self.z == 0:
            return TEAffinePoint(0, 1, self.curve) # Identity
        
        p = self.curve.PRIME_FIELD
        inv_z = pow(self.z, -1, p)
        x = (self.x * inv_z) % p
        y = (self.y * inv_z) % p
        return TEAffinePoint(x, y, self.curve)

    @classmethod
    def zero(cls, curve: C) -> Self:
        """Identity point (0, 1) -> (0:1:1:0)"""
        return cls(0, 1, 1, 0, curve)

    def double(self) -> Self:
        # A = X1^2
        # B = Y1^2
        # C = 2 * Z1^2
        # D = a * A
        # E = (X1 + Y1)^2 - A - B
        # G = D + B
        # F = G - C
        # H = D - B
        # X3 = E * F
        # Y3 = G * H
        # T3 = E * H
        # Z3 = F * G
        
        p = self.curve.PRIME_FIELD
        a_coeff = self.curve.EdwardsA
        
        A = (self.x * self.x) % p
        B = (self.y * self.y) % p
        C = (2 * self.z * self.z) % p
        D = (a_coeff * A) % p
        
        x_plus_y = self.x + self.y
        E = (x_plus_y * x_plus_y - A - B) % p
        
        G = (D + B) % p
        F = (G - C) % p
        H = (D - B) % p
        
        x3 = (E * F) % p
        y3 = (G * H) % p
        t3 = (E * H) % p
        z3 = (F * G) % p
        
        return self.__class__(x3, y3, z3, t3, self.curve)

    def __add__(self, other: Self) -> Self:
        # A = X1*X2
        # B = Y1*Y2
        # C = d*T1*T2
        # D = Z1*Z2
        # E = (X1+Y1)*(X2+Y2)-A-B
        # F = D-C
        # G = D+C
        # H = B-a*A
        # X3 = E*F
        # Y3 = G*H
        # T3 = E*H
        # Z3 = F*G
        
        p = self.curve.PRIME_FIELD
        a_coeff = self.curve.EdwardsA
        d_coeff = self.curve.EdwardsD
        
        A = (self.x * other.x) % p
        B = (self.y * other.y) % p
        C = (d_coeff * self.t * other.t) % p
        D = (self.z * other.z) % p
        
        E = ((self.x + self.y) * (other.x + other.y) - A - B) % p
        F = (D - C) % p
        G = (D + C) % p
        H = (B - a_coeff * A) % p
        
        x3 = (E * F) % p
        y3 = (G * H) % p
        t3 = (E * H) % p
        z3 = (F * G) % p
        
        return self.__class__(x3, y3, z3, t3, self.curve)
