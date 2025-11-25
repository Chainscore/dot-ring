from typing import Tuple
from py_ecc.bls import point_compression
from py_ecc.optimized_bls12_381 import FQ, FQ2, is_on_curve


class Helpers:
    @staticmethod
    def knocker_delta(i, j):
        """ "
        input:i,j
        output: return 1 if i==j 0 otherwise
        """
        return 1 if i == j else 0

    @staticmethod
    def unzip(points):
        """ "
        input:Gets a list of points as input
        output:Splits the points into x,y co-ordinates
        """
        x_c = [pt[0] for pt in points]
        y_c = [pt[1] for pt in points]
        return x_c, y_c

    @staticmethod
    # bls point to string
    def bls_g1_compress(bls_point):
        if len(bls_point) == 2:
            point = (FQ(bls_point[0]), FQ(bls_point[1]), FQ(1))
        else:
            point = (FQ(bls_point[0]), FQ(bls_point[1]), FQ(bls_point[2]))

        # Compress the point
        compressed = point_compression.compress_G1(point)
        hex_rep = compressed.to_bytes(48, "big").hex()
        return hex_rep

    @staticmethod
    def bls_g1_decompress(byte_array: bytes | str) -> Tuple[FQ, FQ, FQ]:
        """
        Decompress a BLS G1 point from its byte representation.

        Args:
            byte_array (bytes | str): Byte array or hex string representing the compressed point.

        Returns:
            Tuple[FQ, FQ, FQ]: Decompressed point in Jacobian coordinates.
        """
        # Fast path: use BLST directly if available
        try:
            import blst
            if isinstance(byte_array, str):
                byte_array = bytes.fromhex(byte_array)
            p1_affine = blst.P1_Affine(byte_array)
            affine_bytes = p1_affine.serialize()
            # TODO: Alt we could recover x,y from compressed bytes directly
            x = int.from_bytes(affine_bytes[:48], "big")
            y = int.from_bytes(affine_bytes[48:], "big")
            return (FQ(x), FQ(y), FQ(1))
        except (ImportError, Exception):
            # Fallback to py_ecc
            if isinstance(byte_array, bytes):
                byte_array = byte_array.hex()
                dcp_scalar = int(byte_array, 16)
            else:
                dcp_scalar = int(byte_array, 16)
            decompressed = point_compression.decompress_G1(dcp_scalar)
            assert is_on_curve(decompressed, 4), "INVALID POINT"
            return decompressed

    @staticmethod
    def bls_g2_compress(g2_point):
        if len(g2_point) == 3:
            x, y, z = g2_point
            point = (FQ2([x.coeffs[0], x.coeffs[1]]) if hasattr(x, 'coeffs') else x, 
                    FQ2([y.coeffs[0], y.coeffs[1]]) if hasattr(y, 'coeffs') else y, 
                    FQ2([z.coeffs[0], z.coeffs[1]]) if hasattr(z, 'coeffs') else z)
        else:
            x, y = g2_point
            point = (FQ2([x.coeffs[0], x.coeffs[1]]) if hasattr(x, 'coeffs') else x, 
                    FQ2([y.coeffs[0], y.coeffs[1]]) if hasattr(y, 'coeffs') else y, 
                    FQ2([1, 0]))
        
        # compress the point
        compressed = point_compression.compress_G2(point)
        return compressed[0].to_bytes(48, 'big').hex() + compressed[1].to_bytes(48, 'big').hex()

    @staticmethod
    # for fiat_shamir
    def to_int(tup):
        x, y = tup
        res = int(x), int(y)
        return res

    @staticmethod
    # int to hex_string
    def to_bytes(val):
        res = val.to_bytes(32, "little")
        return res.hex()

    @staticmethod
    def altered_points(g2_points):
        res = [(b, a) for pair in g2_points for point in pair for a, b in [point]]
        return res

    @staticmethod
    def to_scalar_int(string) -> int:
        if isinstance(string, bytes):
            return int.from_bytes(string, "little")
        byts = bytes.fromhex(string)
        return int.from_bytes(byts, "little")

    @staticmethod
    def bls_projective_2_affine(points_3d):
        """
        Convert a list of 3D coordinate points to 2D by removing the z-coordinate.
        """
        return [(x, y) for x, y, z in points_3d]

    @staticmethod
    def to_fq(point):
        """convert a int type point cords to FQ type"""
        x, y, z = point
        res = (FQ(x), FQ(y), FQ(z))
        return res

    @staticmethod
    def l_endian_2_int(byte_array: bytes) -> int:
        if isinstance(byte_array, str):
            return int.from_bytes(bytes.fromhex(byte_array), "little")
        return int.from_bytes(byte_array, "little")

    @staticmethod
    def str_to_int(byte_array: bytes, order: str) -> int:
        if isinstance(byte_array, str):
            return int.from_bytes(bytes.fromhex(byte_array), order)
        return int.from_bytes(byte_array, order)

    @staticmethod
    def int_to_str(val: int, order: str, n_bytes: int = 32):
        return val.to_bytes(n_bytes, order)

    @staticmethod
    def b_endian_2_int(byte_array: bytes) -> int:
        if isinstance(byte_array, str):
            return int.from_bytes(bytes.fromhex(byte_array), "big")
        return int.from_bytes(byte_array, "big")

    @staticmethod
    def to_b_endian(val: int, n_bytes: int = 32) -> bytes:
        return val.to_bytes(n_bytes, "big")

    @staticmethod
    def to_l_endian(val: int, n_bytes: int = 32) -> bytes:
        return val.to_bytes(n_bytes, "little")

    @staticmethod
    def pt_len(prime_field: int) -> int:
        coord_size = (prime_field.bit_length() + 7) // 8
        return coord_size