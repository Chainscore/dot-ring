from dot_ring.curve.specs.bandersnatch import BandersnatchPoint
from typing import  Tuple

class TwistedEdwardCurve:
    @staticmethod
    def mul(k, point):
        """Multiply a point by a scalar on Bandersnatch  Elliptic Curve"""
        res=BandersnatchPoint(point[0], point[1])*k
        return res.x, res.y

    @staticmethod
    def add(point1:Tuple[int,int],point2:Tuple[int,int]):
        """Point Addition for Two input Points on a Bandersnatch Elliptic Curve"""
        x1, y1 = point1
        x2, y2 = point2
        res=BandersnatchPoint(x1, y1)+BandersnatchPoint(x2, y2)
        return res.x, res.y