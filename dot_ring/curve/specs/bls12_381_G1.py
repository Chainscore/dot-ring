from __future__ import annotations

from dataclasses import dataclass
from typing import Final, Self, Any

from dot_ring.curve.e2c import E2C_Variant
from ..glv import DisabledGLV
from ..short_weierstrass.sw_curve import SWCurve
from ..short_weierstrass.sw_affine_point import SWAffinePoint


@dataclass(frozen=True)
class BLS12_381_G1Params:
    """
    Parameters for the BLS12-381 G1 curve (Weierstrass form).

    NOTE: This is the commonly-used BLS12-381 curve where the curve equation
    for G1 is:
        y^2 = x^3 + 4  (over F_p)

    The values below are the standard constants used by many implementations
    (noble-curves, zkcrypto/arkworks, etc.).
    """

    # Domain separation / hash-to-curve strings (RFC drafts / implementations)
    SUITE_STRING: Final[bytes] = b"BLS12381G1_XMD:SHA-256_SSWU_NU_"
    DST: Final[bytes] = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_NU_"  # common default DST

    # Prime field p (F_q) for BLS12-381

    PRIME_FIELD: Final[int] = 0x1A0111EA397FE69A4B1BA7B6434BACD7_64774B84F38512BF6730D2A0F6B0F624_1EABFFFEB153FFFFB9FEFFFFFFFFAAAB

    # Order r of the prime-order subgroup (G1 and G2 share the same r)
    ORDER: Final[int] = 0x73EDA753299D7D483339D80809A1D805_53BDA402FFFE5BFEFFFFFFFF00000001

    # Cofactor for G1 (h1)
    COFACTOR: Final[int] = 0xd201000000010001

    # Generator point (affine coordinates) for G1 (from standard definitions)
    GENERATOR_X: Final[int] = 0x17F1D3A73197D7942695638C4FA9AC0F_C3688C4F9774B905A14E3A3F171BAC58_6C55E83FF97A1AEFFB3AF00ADB22C6BB
    GENERATOR_Y: Final[int] = 0x08B3F481E3AAA0F1A09E30ED741D8AE4_FCF5E095D5D00AF600DB18CB2C04B3ED_D03CC744A2888AE40CAA232946C5E7E1

    # Short Weierstrass parameters for y^2 = x^3 + a*x + b
    WEIERSTRASS_A: Final[int] = 0x00
    WEIERSTRASS_B: Final[int] = 0x04

    # Parameters useful for hash-to-curve (SSWU) - implementations differ,
    # but the curve uses a small non-zero Z for the map. Many implementations
    # expose a Z constant per-curve; set a sensible default here.
    Z: Final[int] = 11

    # Field/encoding sizes
    M: Final[int] = 1  # extension degree for G1 (over Fp)
    K: Final[int] = 128  # approximate security level in bits
    L: Final[int] = 64 # field element encoded length in bytes (381 bits -> 48 bytes)
    S_IN_BYTES: Final[int] =64

    # Hash used by default in hash-to-curve suites for this curve
    H_A: Final[str] = "SHA-256"

    # Challenge length for VRF / challenge bytes (48 bytes is typical for 381-bit)
    CHALLENGE_LENGTH: Final[int] = 48

    # Flags / optional fields
    Requires_Isogeny: Final[bool] = True
    BBx: Final[int | None] = None
    BBy: Final[int | None] = None
    Isogeny_Coeffs: Final[object | None] = None


class BLS12_381_G1Curve(SWCurve):
    """
    BLS12-381 G1 curve implementation (short Weierstrass form).

    This class wraps the curve parameters and passes them to the SWCurve base
    implementation used in this codebase.
    """

    @property
    def CHALLENGE_LENGTH(self) -> int:
        return BLS12_381_G1Params.CHALLENGE_LENGTH

    def __init__(self) -> None:
        super().__init__(
            PRIME_FIELD=BLS12_381_G1Params.PRIME_FIELD,
            ORDER=BLS12_381_G1Params.ORDER,
            GENERATOR_X=BLS12_381_G1Params.GENERATOR_X,
            GENERATOR_Y=BLS12_381_G1Params.GENERATOR_Y,
            COFACTOR=BLS12_381_G1Params.COFACTOR,
            glv=DisabledGLV,
            Z=BLS12_381_G1Params.Z,
            WeierstrassA=BLS12_381_G1Params.WEIERSTRASS_A,
            WeierstrassB=BLS12_381_G1Params.WEIERSTRASS_B,
            SUITE_STRING=BLS12_381_G1Params.SUITE_STRING,
            DST=BLS12_381_G1Params.DST,
            E2C=E2C_Variant.SSWU,
            BBx=BLS12_381_G1Params.BBx,
            BBy=BLS12_381_G1Params.BBy,
            M=BLS12_381_G1Params.M,
            K=BLS12_381_G1Params.K,
            L=BLS12_381_G1Params.L,
            S_in_bytes=BLS12_381_G1Params.S_IN_BYTES,
            H_A=BLS12_381_G1Params.H_A,
            Requires_Isogeny=BLS12_381_G1Params.Requires_Isogeny,
            Isogeny_Coeffs=BLS12_381_G1Params.Isogeny_Coeffs,
        )


# Singleton instance for convenience
BLS12_381_G1Curve: Final[BLS12_381_G1Curve] = BLS12_381_G1Curve()


@dataclass(frozen=True)
class BLS12_381_G1Point(SWAffinePoint):
    """
    Affine point on BLS12-381 G1.
    """
    curve: Final[BLS12_381_G1Curve] = BLS12_381_G1Curve

    def __init__(self, x: int, y: int) -> None:
        super().__init__(x, y, self.curve)

    @classmethod
    def generator_point(cls) -> Self:
        return cls(
            BLS12_381_G1Params.GENERATOR_X,
            BLS12_381_G1Params.GENERATOR_Y,
        )

    @classmethod
    def map_to_curve_simple_swu(cls, u: int) -> BLS12_381_G1Point | Any:
        """Implements simplified SWU mapping"""
        # 1.  tv1 = inv0(Z^2 * u^4 + Z * u^2)
        # 2.   x1 = (-B / A) * (1 + tv1)
        # 3.  If tv1 == 0, set x1 = B / (Z * A)
        # 4. gx1 = x1^3 + A * x1 + B
        # 5.  x2 = Z * u^2 * x1
        # 6. gx2 = x2^3 + A * x2 + B
        # 7.  If is_square(gx1), set x = x1 and y = sqrt(gx1)
        # 8.  Else set x = x2 and y = sqrt(gx2)
        # 9.  If sgn0(u) != sgn0(y), set y = -y
        # 10. return (x, y)

        Z = cls.curve.Z
        A = cls.curve.WeierstrassA
        B = cls.curve.WeierstrassB
        p = cls.curve.PRIME_FIELD

        if cls.curve.Requires_Isogeny:  # E' vals, used only for secp256k1 as its A=0
            A= 0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d
            B= 0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0

        # 1. tv1 = inv0(Z^2 * u^4 + Z * u^2)
        u_sq = (u * u) % p
        tv1 = (Z * Z * ((u_sq * u_sq) % p) + Z * u_sq) % p

        # Handle special case when tv1 is 0
        if tv1 == 0:
            # 3. If tv1 == 0, set x1 = B / (Z * A)
            x1 = (B * cls.curve.inv((Z * A) % p)) % p
        else:
            # 2. x1 = (-B / A) * (1 + tv1)
            tv1 = cls.curve.inv(tv1)
            x1 = (-B * cls.curve.inv(A)) % p
            x1 = (x1 * (1 + tv1)) % p

        # 4. gx1 = x1^3 + A * x1 + B
        gx1 = (pow(x1, 3, p) + (A * x1) % p + B) % p

        # 5. x2 = Z * u^2 * x1
        x2 = (Z * u_sq % p) * x1 % p

        # 6. gx2 = x2^3 + A * x2 + B
        gx2 = (pow(x2, 3, p) + (A * x2) % p + B) % p

        # 7-8. Find a valid x and y
        x, y = x1, None
        if cls.curve.is_square(gx1):
            y = cls.curve.mod_sqrt(gx1)
        else:
            x = x2
            y = cls.curve.mod_sqrt(gx2)

        # 9. Fix sign of y
        if cls.curve.sgn0(u) != cls.curve.sgn0(y):
            y = (-y) % p

        params={
                "k_1": [
                    "0x11a05f2b1e833340b809101dd99815856b303e88a2d7005ff2627b56cdb4e2c85610c2d5f2e62d6eaeac1662734649b7",
                    "0x17294ed3e943ab2f0588bab22147a81c7c17e75b2f6a8417f565e33c70d1e86b4838f2a6f318c356e834eef1b3cb83bb",
                    "0xd54005db97678ec1d1048c5d10a9a1bce032473295983e56878e501ec68e25c958c3e3d2a09729fe0179f9dac9edcb0",
                    "0x1778e7166fcc6db74e0609d307e55412d7f5e4656a8dbf25f1b33289f1b330835336e25ce3107193c5b388641d9b6861",
                    "0xe99726a3199f4436642b4b3e4118e5499db995a1257fb3f086eeb65982fac18985a286f301e77c451154ce9ac8895d9",
                    "0x1630c3250d7313ff01d1201bf7a74ab5db3cb17dd952799b9ed3ab9097e68f90a0870d2dcae73d19cd13c1c66f652983",
                    "0xd6ed6553fe44d296a3726c38ae652bfb11586264f0f8ce19008e218f9c86b2a8da25128c1052ecaddd7f225a139ed84",
                    "0x17b81e7701abdbe2e8743884d1117e53356de5ab275b4db1a682c62ef0f2753339b7c8f8c8f475af9ccb5618e3f0c88e",
                    "0x80d3cf1f9a78fc47b90b33563be990dc43b756ce79f5574a2c596c928c5d1de4fa295f296b74e956d71986a8497e317",
                    "0x169b1f8e1bcfa7c42e0c37515d138f22dd2ecb803a0c5c99676314baf4bb1b7fa3190b2edc0327797f241067be390c9e",
                     "0x10321da079ce07e272d8ec09d2565b0dfa7dccdde6787f96d50af36003b14866f69b771f8c285decca67df3f1605fb7b",
                     "0x6e08c248e260e70bd1e962381edee3d31d79d7e22c837bc23c0bf1bc24c6b68c24b1b80b64d391fa9c8ba2e8ba2d229"
                ],
                "k_2":[
                    "0x8ca8d548cff19ae18b2e62f4bd3fa6f01d5ef4ba35b48ba9c9588617fc8ac62b558d681be343df8993cf9fa40d21b1c",
                    "0x12561a5deb559c4348b4711298e536367041e8ca0cf0800c0126c2588c48bf5713daa8846cb026e9e5c8276ec82b3bff",
                    "0xb2962fe57a3225e8137e629bff2991f6f89416f5a718cd1fca64e00b11aceacd6a3d0967c94fedcfcc239ba5cb83e19",
                    "0x3425581a58ae2fec83aafef7c40eb545b08243f16b1655154cca8abc28d6fd04976d5243eecf5c4130de8938dc62cd8",
                    "0x13a8e162022914a80a6f1d5f43e7a07dffdfc759a12062bb8d6b44e833b306da9bd29ba81f35781d539d395b3532a21e",
                    "0xe7355f8e4e667b955390f7f0506c6e9395735e9ce9cad4d0a43bcef24b8982f7400d24bc4228f11c02df9a29f6304a5",
                    "0x772caacf16936190f3e0c63e0596721570f5799af53a1894e2e073062aede9cea73b3538f0de06cec2574496ee84a3a",
                    "0x14a7ac2a9d64a8b230b3f5b074cf01996e7f63c21bca68a81996e1cdf9822c580fa5b9489d11e2d311f7d99bbdcc5a5e",
                    "0xa10ecf6ada54f825e920b3dafc7a3cce07f8d1d7161366b74100da67f39883503826692abba43704776ec3a79a1d641",
                    "0x95fc13ab9e92ad4476d6e3eb3a56680f682b4ee96f7d03776df533978f31c1593174e4b4b7865002d6384d168ecdd0a"
                ],
                "k_3": [
                    "0x90d97c81ba24ee0259d1f094980dcfa11ad138e48a869522b52af6c956543d3cd0c7aee9b3ba3c2be9845719707bb33",
                    "0x134996a104ee5811d51036d776fb46831223e96c254f383d0f906343eb67ad34d6c56711962fa8bfe097e75a2e41c696",
                    "0xcc786baa966e66f4a384c86a3b49942552e2d658a31ce2c344be4b91400da7d26d521628b00523b8dfe240c72de1f6",
                    "0x1f86376e8981c217898751ad8746757d42aa7b90eeb791c09e4a3ec03251cf9de405aba9ec61deca6355c77b0e5f4cb",
                    "0x8cc03fdefe0ff135caf4fe2a21529c4195536fbe3ce50b879833fd221351adc2ee7f8dc099040a841b6daecf2e8fedb",
                    "0x16603fca40634b6a2211e11db8f0a6a074a7d0d4afadb7bd76505c3d3ad5544e203f6326c95a807299b23ab13633a5f0",
                    "0x4ab0b9bcfac1bbcb2c977d027796b3ce75bb8ca2be184cb5231413c4d634f3747a87ac2460f415ec961f8855fe9d6f2",
                    "0x987c8d5333ab86fde9926bd2ca6c674170a05bfe3bdd81ffd038da6c26c842642f64550fedfe935a15e4ca31870fb29",
                    "0x9fc4018bd96684be88c9e221e4da1bb8f3abd16679dc26c1e8b6e6a1f20cabe69d65201c78607a360370e577bdba587",
                    "0xe1bba7a1186bdb5223abde7ada14a23c42a0ca7915af6fe06985e7ed1e4d43b9b3f7055dd4eba6f2bafaaebca731c30",
                     "0x19713e47937cd1be0dfd0b8f1d43fb93cd2fcbcb6caf493fd1183e416389e61031bf3a5cce3fbafce813711ad011c132",
                     "0x18b46a908f36f6deb918c143fed2edcc523559b8aaf0c2462e6bfe7f911f643249d9cdf41b44d606ce07c8a4d0074d8e",
                     "0xb182cac101b9399d155096004f53f447aa7b12a3426b08ec02710e807b4633f06c851c1919211f20d4c04f00b971ef8",
                     "0x245a394ad1eca9b72fc00ae7be315dc757b3b080d4c158013e6632d3c40659cc6cf90ad1c232a6442d9d3f5db980133",
                     "0x5c129645e44cf1102a159f748c4a3fc5e673d81d7e86568d9ab0f5d396a7ce46ba1049b6579afb7866b1e715475224b",
                     "0x15e6be4e990f03ce4ea50b3b42df2eb5cb181d8f84965a3957add4fa95af01b2b665027efec01c7704b456be69c8b604"
                ],
                "k_4": [
                    "0x16112c4c3a9c98b252181140fad0eae9601a6de578980be6eec3232b5be72e7a07f3688ef60c206d01479253b03663c1",
                    "0x1962d75c2381201e1a0cbd6c43c348b885c84ff731c4d59ca4a10356f453e01f78a4260763529e3532f6102c2e49a03d",
                    "0x58df3306640da276faaae7d6e8eb15778c4855551ae7f310c35a5dd279cd2eca6757cd636f96f891e2538b53dbf67f2",
                    "0x16b7d288798e5395f20d23bf89edb4d1d115c5dbddbcd30e123da489e726af41727364f2c28297ada8d26d98445f5416",
                    "0xbe0e079545f43e4b00cc912f8228ddcc6d19c9f0f69bbb0542eda0fc9dec916a20b15dc0fd2ededda39142311a5001d",
                    "0x8d9e5297186db2d9fb266eaac783182b70152c65550d881c5ecd87b6f0f5a6449f38db9dfa9cce202c6477faaf9b7ac",
                    "0x166007c08a99db2fc3ba8734ace9824b5eecfdfa8d0cf8ef5dd365bc400a0051d5fa9c01a58b1fb93d1a1399126a775c",
                    "0x16a3ef08be3ea7ea03bcddfabba6ff6ee5a4375efa1f4fd7feb34fd206357132b920f5b00801dee460ee415a15812ed9",
                    "0x1866c8ed336c61231a1be54fd1d74cc4f9fb0ce4c6af5920abc5750c4bf39b4852cfe2f7bb9248836b233d9d55535d4a",
                    "0x167a55cda70a6e1cea820597d94a84903216f763e13d87bb5308592e7ea7d4fbc7385ea3d529b35e346ef48bb8913f55",
                     "0x4d2f259eea405bd48f010a01ad2911d9c6dd039bb61a6290e591b36e636a5c871a5c29f4f83060400f8b49cba8f6aa8",
                     "0xaccbb67481d033ff5852c1e48c50c477f94ff8aefce42d28c0f9a88cea7913516f968986f7ebbea9684b529e2561092",
                     "0xad6b9514c767fe3c3613144b45f1496543346d98adf02267d5ceef9a00d9b8693000763e3b90ac11e99b138573345cc",
                     "0x2660400eb2e4f3b628bdd0d53cd76f2bf565b94e72927c1cb748df27942480e420517bd8714cc80d1fadc1326ed06f7",
                     "0xe0fa1d816ddc03e6b24255e0d7819c171c40f65e273b853324efcd6356caa205ca2f570f13497804415473a1d634b8f"
                ]
            }

        if cls.curve.Requires_Isogeny:

            k1 = [int(c, 16) for c in params["k_1"][::-1]]  # k_(1,11) .. k_(1,0)
            k2 = [int(c, 16) for c in params["k_2"][::-1]]  # k_(2,9) .. k_(2,0)
            k3 = [int(c, 16) for c in params["k_3"][::-1]]  # k_(3,15) .. k_(3,0)
            k4 = [int(c, 16) for c in params["k_4"][::-1]]  # k_(4,14) .. k_(4,0)
            xp,yp=x,y

            # Compute x numerator
            x_num = (
                            k1[0] * xp ** 11 + k1[1] * xp ** 10 + k1[2] * xp ** 9 + k1[3] * xp ** 8 + k1[4] * xp ** 7 +
                            k1[5] * xp ** 6 + k1[6] * xp ** 5 + k1[7] * xp ** 4 + k1[8] * xp ** 3 + k1[9] * xp ** 2 +
                            k1[10] * xp + k1[11]
                    ) % p

            # Compute x denominator
            x_den = (
                            xp ** 10 + k2[0] * xp ** 9 + k2[1] * xp ** 8 + k2[2] * xp ** 7 + k2[3] * xp ** 6 +
                            k2[4] * xp ** 5 + k2[5] * xp ** 4 + k2[6] * xp ** 3 + k2[7] * xp ** 2 + k2[8] * xp +
                            k2[9]
                    ) % p

            x = (x_num * pow(x_den, -1, p)) % p  # multiply by modular inverse

            # Compute y numerator
            y_num = (
                            k3[0] * xp ** 15 + k3[1] * xp ** 14 + k3[2] * xp ** 13 + k3[3] * xp ** 12 + k3[
                        4] * xp ** 11 +
                            k3[5] * xp ** 10 + k3[6] * xp ** 9 + k3[7] * xp ** 8 + k3[8] * xp ** 7 + k3[9] * xp ** 6 +
                            k3[10] * xp ** 5 + k3[11] * xp ** 4 + k3[12] * xp ** 3 + k3[13] * xp ** 2 + k3[14] * xp +
                            k3[15]
                    ) % p

            # Compute y denominator
            y_den = (
                            xp ** 15 + k4[0] * xp ** 14 + k4[1] * xp ** 13 + k4[2] * xp ** 12 + k4[3] * xp ** 11 +
                            k4[4] * xp ** 10 + k4[5] * xp ** 9 + k4[6] * xp ** 8 + k4[7] * xp ** 7 + k4[8] * xp ** 6 +
                            k4[9] * xp ** 5 + k4[10] * xp ** 4 + k4[11] * xp ** 3 + k4[12] * xp ** 2 + k4[13] * xp +
                            k4[14]
                    ) % p

            y = (yp * y_num * pow(y_den, -1, p)) % p

        return cls(x=x, y=y)

