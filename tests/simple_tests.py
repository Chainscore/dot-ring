from dot_ring.curve.specs.baby_jubjub import BabyJubJub_TE_Curve, BabyJubJubPoint
from dot_ring.curve.specs.bandersnatch import Bandersnatch_TE_Curve, BandersnatchPoint
from dot_ring.curve.specs.ed25519 import Ed25519_TE_Curve, Ed25519Point
from dot_ring.curve.specs.jubjub import JubJub_TE_Curve, JubJubPoint
from dot_ring.ring_proof.helpers import Helpers
from dot_ring.vrf.ietf.ietf import IETF_VRF
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

#For IETF VRF

#Generate IETF Proof
vrf = IETF_VRF(Bandersnatch_TE_Curve, BandersnatchPoint)

secret_key="3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18"
secret_key=Helpers.l_endian_2_int(secret_key)
alpha=b""
add=b""
output_point, proof = vrf.prove(
    alpha,
    secret_key,
    add,
)
print("Output_Put", (output_point.x, output_point.y))
print("IETF_Proof", proof)

#Verify IETF Proof
input_point=BandersnatchPoint.encode_to_curve(alpha)
public_key="a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b"
pub_key=BandersnatchPoint.string_to_point(public_key)

verified= vrf.verify(
    pub_key,
    input_point,
    add,
    output_point,
    proof,
)
print("Is Signature Verfified:", verified)

#For Pedersen VRF
#proof
vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
blinding_factor = "01371ac62e04d1faaadbebaa686aaf122143e2cda23aacbaa4796d206779a501"
blinding_factor=Helpers.l_endian_2_int(blinding_factor)

output_point, proof = vrf.prove(
                    alpha,
                    secret_key,
                    add,
                    blinding_factor,
                )

print("Output_Point:", output_point.point_to_string().hex())
print("Pedersen Proof", proof)


#verfify pedersen proof
p_proof_valid= vrf.verify(
        input_point, add , output_point, proof
    )
print("is Pedersen Proof valid:", p_proof_valid)


# vrf= PedersenVRF(JubJub_TE_Curve,JubJubPoint)
# blinding_factor = "01371ac62e04d1faaadbebaa686aaf122143e2cda23aacbaa4796d206779a501"
# blinding_factor=Helpers.l_endian_2_int(blinding_factor) % Ed25519_TE_Curve.PRIME_FIELD
# output_point, proof = vrf.prove(
#                     alpha,
#                     secret_key,
#                     add,
#                     blinding_factor,
#                 )
# print("Output_Point:", output_point.point_to_string().hex())
# print("Pedersen Proof", proof)


# vrf= PedersenVRF(Ed25519_TE_Curve,Ed25519Point)
# vrf = PedersenVRF(BabyJubJub_TE_Curve,BabyJubJubPoint )

