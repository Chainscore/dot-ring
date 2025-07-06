# mypy: ignore-errors
from dot_ring.curves.specs.bandersnatch import _Params as BandersnatchParams, BandersnatchCurve, BandersnatchPoint
from dot_ring.curves.twisted_edwards.te_affine_point import TEAffinePoint
from dot_ring.curves.twisted_edwards.te_curve import TECurve
from dot_ring.ring_proof.constants import S_PRIME

from typing import  Tuple,List, Any
class TwistedEdwardCurve:
    @staticmethod
    def mul(k, point):
        """Multiply a point by a scalar on Bandersnaftch  Elliptic Curve"""

        result = (0, 1)
        addend = point
        while k:
            if k& 1:
                result = TwistedEdwardCurve.add(result, addend)
            addend = TwistedEdwardCurve.point_double(addend)
            k >>= 1

        # pnt= BandersnatchPoint(point[0], point[1])
        # pnt_scalar= pnt*k
        # result= (pnt_scalar.x, pnt_scalar.y)

        return result


    @staticmethod
    def add(point1:Tuple[int,int],point2:Tuple[int,int]):
        """Point Addition for Two input Points on a Bandersnatch Elliptic Curve"""

        x1, y1 = point1
        x2, y2 = point2
        if point1 == point2:
            return TwistedEdwardCurve.point_double(point1)

        if point1 == (0, 1):
            return point2
        if point2 == (0, 1):
            return point1

        x1y2 = (x1 * y2) % S_PRIME
        y1x2 = (y1 * x2) % S_PRIME
        y1y2 = (y1 * y2) % S_PRIME
        x1x2 = (x1 * x2) % S_PRIME
        dx1x2y1y2 = (BandersnatchParams.EDWARDS_D * x1x2 * y1y2) % S_PRIME

        x3 = ((x1y2 + y1x2) * TwistedEdwardCurve.mod_inverse(1 + dx1x2y1y2)) % S_PRIME
        y3 = ((y1y2 - BandersnatchParams.EDWARDS_A * x1x2) * TwistedEdwardCurve.mod_inverse(
            1 - dx1x2y1y2)) % S_PRIME

        return x3, y3


    @staticmethod
    def point_double(point:Tuple[int,int]):
        """Point doubling on the twisted Edwards curve."""
        x1, y1 = point

        # Check if the point is at infinity (identity element)
        if y1 == 0:
            return (0, 1)  # Return the identity point in twisted Edwards form

        # Calculate new coordinates using the doubling formula
        denom_x = (BandersnatchParams.EDWARDS_A * x1 ** 2 + y1 ** 2) % S_PRIME
        denom_y = (2 - BandersnatchParams.EDWARDS_A * x1 ** 2 - y1 ** 2) % S_PRIME
        if denom_x == 0 or denom_y == 0:
            return (0, 1)  # Return identity if denominator is zero

        x3 = (2 * x1 * y1 * TwistedEdwardCurve.mod_inverse(denom_x)) % S_PRIME
        y3 = ((y1 ** 2 - BandersnatchParams.EDWARDS_A * x1 ** 2) *TwistedEdwardCurve. mod_inverse(denom_y)) % S_PRIME

        return (x3, y3)


    @staticmethod
    def mod_inverse(val:int)->int:
        """Finds the Mod Inverse Using Fermat's little Theorem"""


        if pow(val,  S_PRIME- 1, S_PRIME) != 1:
            raise ValueError("No inverse exists")


        return pow(val, S_PRIME- 2, S_PRIME)


    @staticmethod
    def point_neg(point: Tuple[int, int]) -> Tuple[int, int]:
        """Negate a point on the curve."""

        x, y = point
        return -x % S_PRIME, y

    @staticmethod
    def point_subtract(point1: Tuple[int, int], point2: Tuple[int, int]) -> Tuple[int, int]:
        """Subtract two points."""

        return TwistedEdwardCurve.add( point1,TwistedEdwardCurve.point_neg(point2))


    @staticmethod
    def is_square(x: int) -> bool:
        """Check if x is a quadratic residue modulo p."""
        if x == 0:
            return True
        return pow(x, (S_PRIME - 1) // 2, S_PRIME)==1


    @staticmethod
    def mod_sqrt(a: int) -> int:
        """Calculate modular square root using Tonelli-Shanks algorithm"""

        if a == 0:
            return 0
        if not TwistedEdwardCurve.is_square(a):
            raise ValueError("No square root exists")

        q = S_PRIME - 1
        s = 0
        while q % 2 == 0:
            q //= 2
            s += 1

        if s == 1:
            return pow(a, (S_PRIME + 1) // 4, S_PRIME)

        z = 2
        while TwistedEdwardCurve.is_square(z):
            z += 1

        m = s
        c = pow(z, q, S_PRIME)
        t = pow(a, q, S_PRIME)
        r = pow(a, (q + 1) // 2, S_PRIME)


        while t != 1:
            i = 0
            temp = t
            while temp != 1:
                temp = (temp * temp) % S_PRIME
                i += 1
                if i == m:
                    return 0

            b = pow(c, 1 << (m - i - 1), S_PRIME)
            m = i
            c = (b * b) % S_PRIME
            t = (t * c) % S_PRIME
            r = (r * b) % S_PRIME

        return r
