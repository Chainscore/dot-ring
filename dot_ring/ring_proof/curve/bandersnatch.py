from typing import cast

from dot_ring.curve.specs.bandersnatch import BandersnatchPoint
from dot_ring.curve.twisted_edwards.te_affine_point import TEAffinePoint


class TwistedEdwardCurve:
    @staticmethod
    def mul(
        k: int,
        point: tuple[int | tuple[int, int] | None, int | tuple[int, int] | None],
    ) -> tuple[int | tuple[int, int] | None, int | tuple[int, int] | None]:
        """Multiply a point by a scalar on Bandersnatch  Elliptic Curve"""
        res = BandersnatchPoint(cast(int, point[0]), cast(int, point[1])) * k
        return res.x, res.y

    @staticmethod
    def add(
        point1: tuple[int | tuple[int, int] | None, int | tuple[int, int] | None],
        point2: tuple[int | tuple[int, int] | None, int | tuple[int, int] | None],
    ) -> tuple[int | tuple[int, int] | None, int | tuple[int, int] | None]:
        """Point Addition for Two input Points on a Bandersnatch Elliptic Curve"""
        x1, y1 = point1
        x2, y2 = point2
        p1 = cast(TEAffinePoint, BandersnatchPoint(cast(int, x1), cast(int, y1)))
        p2 = cast(TEAffinePoint, BandersnatchPoint(cast(int, x2), cast(int, y2)))
        res = cast(BandersnatchPoint, p1 + p2)  # type: ignore[operator]
        return res.x, res.y
