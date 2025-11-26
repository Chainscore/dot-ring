from __future__ import annotations
from dataclasses import dataclass
from typing import TypeVar, Self, TYPE_CHECKING, Generic

if TYPE_CHECKING:
    from .te_curve import TECurve
    from .te_affine_point import TEAffinePoint
    from ..point import CurvePoint

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
    def from_point(
        cls, point: CurvePoint
    ) -> Self:
        return cls(point.x, point.y, 1, (point.x * point.y) % point.curve.PRIME_FIELD, point.curve)

    @classmethod
    def from_affine(cls, point: "TEAffinePoint") -> Self:
        return cls(
            point.x, 
            point.y, 
            1, 
            (point.x * point.y) % point.curve.PRIME_FIELD, 
            point.curve
        )

    def to_affine(self, point_cls: type["TEAffinePoint"] | None = None) -> "TEAffinePoint":
        from .te_affine_point import TEAffinePoint as BaseAffine

        target_cls = point_cls or BaseAffine

        # Ensure the target class has a curve reference
        if not hasattr(target_cls, "curve"):
            setattr(target_cls, "curve", self.curve)

        if self.z == 0:
            return target_cls(0, 1)
        
        p = self.curve.PRIME_FIELD
        inv_z = pow(self.z, -1, p)
        x = (self.x * inv_z) % p
        y = (self.y * inv_z) % p
        return target_cls(x, y)

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
        
        # Compute squares
        A = (self.x * self.x) % p
        B = (self.y * self.y) % p
        z_sq = (self.z * self.z) % p
        C = (z_sq << 1) % p  # 2 * z^2 using bit shift
        D = (a_coeff * A) % p
        
        # Compute E efficiently
        x_plus_y = (self.x + self.y) % p
        E = (x_plus_y * x_plus_y - A - B) % p
        
        # Compute remaining terms
        G = (D + B) % p
        F = (G - C) % p
        H = (D - B) % p
        
        # Final coordinates
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
