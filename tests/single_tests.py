#For IETF VRF
import time

from dot_ring.curve.specs.bandersnatch import Bandersnatch_TE_Curve, BandersnatchPoint
from dot_ring.curve.specs.jubjub import JubJub_TE_Curve, JubJubPoint
from dot_ring.ring_proof.helpers import Helpers
from dot_ring.vrf.ietf.ietf import IETF_VRF
from dot_ring.vrf.pedersen.pedersen import PedersenVRF
from dot_ring.vrf.ring.ring_vrf import  RingVrf as RVRF

#Generate IETF Proof
vrf = IETF_VRF(Bandersnatch_TE_Curve, BandersnatchPoint)
secret_key="3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18"
alpha=b""
add=b""
proof= vrf.proof(alpha,secret_key,add)
print("IETF_Proof", proof)


#Verify IETF Proof
input_point=BandersnatchPoint.encode_to_curve(alpha)
public_key="a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b"
p_k=vrf.get_public_key(secret_key)
print("p_k generated:",public_key)
pub_key=BandersnatchPoint.string_to_point(public_key)
verified= vrf.verify(pub_key,input_point,add,proof)
print("Is Signature Verified:", verified)


#For Pedersen VRF
#proof
vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
proof = vrf.proof(alpha,secret_key,add)
print("Pedersen Proof", proof)

#verfify pedersen proof
p_proof_valid= vrf.verify(input_point, add, proof)
print("is Pedersen Proof valid:", p_proof_valid)


#Ring_VRF
B_keys=["5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d",
"3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0",
"aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc",
"3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18",
"7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33",
"48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3",
"f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d"]


s_k="3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18"
p_k="a1b1da71cc4682e159b7da23050d8b6261eb11a3247c89b07ef56ccd002fd38b"
alpha=b""
ad=b""
B_keys=[bytes.fromhex(i) for i in B_keys]
start=time.time()
ring_vrf_proof= RVRF.ring_vrf_proof(alpha, ad,p_k,s_k, B_keys)
print("Ring_VRF_Proof:", ring_vrf_proof)
end=time.time()
print("To generate Proof:", end-start)




#5 RingVrf Proof Verify using (add, ring_root, ring_vrf_proof, message)
add=b"" #conetxt c
RING_ROOT="afd34e92148ec643fbb578f0e14a1ca9369d3e96b821fcc811c745c320fe2264172545ca9b6b1d8a196734bc864e171484f45ba5b95d9be39f03214b59520af3137ea80e302730a5df8e4155003414f6dcf0523d15c6ef5089806e1e8e5782be92e630ae2b14e758ab0960e372172203f4c9a41777dadd529971d7ab9d23ab29fe0e9c85ec450505dde7f5ac038274cf"
Ring_Proof="98bc465cdf55ee0799bc25a80724d02bb2471cd7d065d9bd53a3a7e3416051f6e3686f7c6464c364b9f2b0f15750426a9107bd20fe94a01157764aab5f300d7e2fcba2178cb80851890a656d89550d0bebf60cca8c23575011d2f37cdc06dcdd93818c0c1c3bff5a793d026c604294d0bbd940ec5f1c652bb37dc47564d71dd1aa05aba41d1f0cb7f4442a88d9b533ba8e4788f711abdf7275be66d45d222dde988dedd0cb5b0d36b21ee64e5ef94e26017b674e387baf0f2d8bd04ac6faab057510b4797248e0cb57e03db0199cd77373ee56adb7555928c391de794a07a613f7daac3fc77ff7e7574eaeb0e1a09743c4dae2b420ba59cf40eb0445e41ffb2449021976970c858153505b20ac237bfca469d8b998fc928e9db39a94e2df1740ae0bad6f5d8656806ba24a2f9b89f7a4a9caef4e3ff01fec5982af873143346362a0eb9bb2f6375496ff9388639c7ffeb0bcee33769616e4878fc2315a3ac3518a9da3c4f072e0a0b583436a58524f036c3a1eeca023598682f1132485d3a57088b63acd86c6c72288568db71ff15b7677bfe7218acdebb144a2bf261eb4f65980f830e77f37c4f8d11eac9321f302a089698f3c0079c41979d278e8432405fc14d80aad028f79b0c4c626e4d4ac4e643692a9adfdc9ba2685a6c47eef0af5c8f5d776083895e3e01f1f944cd7547542b7e64b870b1423857f6362533f7cd2a01d231ffed60fe26169c28b28ace1a307fdc8d4b29f0b44659402d3d455d719d896f83b7ee927f0652ca883e4cfa85a2f4f7bc60dda1b068092923076893db5bd477fa2d26173314d7512760521d6ec9f"
ALPHA=b"" #message m

#for sample pedersen proof
gamma="e7aa5154103450f0a0525a36a441f827296ee489ef30ed8787cff8df1bef223f"
proof_pk_com= "3b21abd58807bb6d93797001adaacd7113ec320dcf32d1226494e18a57931fc4"
proof_r= "8123054bfdb6918e0aa25c3337e6509eea262282fd26853bf7cd6db234583f5e"
proof_ok= "ac57ce6a53a887fc59b6aa73d8ff0e718b49bd9407a627ae0e9b9e7c5d0d175b"
proof_s= "0d379b65fb1e6b2adcbf80618c08e31fd526f06c2defa159158f5de146104c0f"
proof_sb= "e2ca83136143e0cac3f7ee863edd3879ed753b995b1ff8d58305d3b1f323630b"

Pedersen_proof=gamma+proof_pk_com+proof_r+proof_ok+ proof_s+proof_sb
signature=Pedersen_proof+Ring_Proof
print("Is The Ring Proof_Valid:", RVRF.ring_vrf_proof_verify(add, RING_ROOT, signature, ALPHA)) #c, r,sign,alpha



# vrf= PedersenVRF(JubJub_TE_Curve,JubJubPoint)
# blinding_factor = "01371ac62e04d1faaadbebaa686aaf122143e2cda23aacbaa4796d206779a501"
# proof = vrf.proof(alpha,secret_key,add,blinding_factor)
# print("Pedersen Proof", proof)
#
# #verfify pedersen proof
# p_proof_valid= vrf.verify(input_point, add, proof)
# print("is Pedersen Proof valid:", p_proof_valid)


# vrf= PedersenVRF(Ed25519_TE_Curve,Ed25519Point)
# vrf = PedersenVRF(BabyJubJub_TE_Curve,BabyJubJubPoint )



#to get the proof
#to verify the proof
#chenged the tests of pedersen and ietf
#change the ring_vrf_tests as well



#changes to be done
#to get the output point, input point, secret_key
#to make the point inside the verify logic as a dynamic point type(for now its Bandersnatch)