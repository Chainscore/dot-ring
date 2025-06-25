#For IETF VRF
from dot_ring.curve.specs.bandersnatch import Bandersnatch_TE_Curve, BandersnatchPoint
from dot_ring.ring_proof.helpers import Helpers
from dot_ring.vrf.ietf.ietf import IETF_VRF
from dot_ring.vrf.pedersen.pedersen import PedersenVRF

#Generate IETF Proof
vrf = IETF_VRF(Bandersnatch_TE_Curve, BandersnatchPoint)
secret_key="3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18"
alpha=b""
add=b""
proof= vrf.prove(alpha,secret_key,add)
print("IETF_Proof", proof)


#Verify IETF Proof
input_point=BandersnatchPoint.encode_to_curve(alpha)
public_key="a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b"
pub_key=BandersnatchPoint.string_to_point(public_key)
verified= vrf.verify(pub_key,input_point,add,proof)
print("Is Signature Verified:", verified)


#For Pedersen VRF
#proof
vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
blinding_factor = "01371ac62e04d1faaadbebaa686aaf122143e2cda23aacbaa4796d206779a501"
proof = vrf.prove(alpha,secret_key,add,blinding_factor)
print("Pedersen Proof", proof)

#verfify pedersen proof
p_proof_valid= vrf.verify(input_point, add, proof)
print("is Pedersen Proof valid:", p_proof_valid)

#to get the proof
#to verify the proof
#chenged the tests of pedersen and ietf
#change the ring_vrf_tests as well


#changes to be done
#to get the output point, input point, secret_key
#to make the point inside the verify logic as a dynamic point type(for now its Bandersnatch)