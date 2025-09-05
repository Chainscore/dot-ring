import time
from dot_ring.curve.specs.bandersnatch import Bandersnatch_TE_Curve, BandersnatchPoint
from dot_ring.vrf.ietf.ietf import IETF_VRF
from dot_ring.vrf.pedersen.pedersen import PedersenVRF
from dot_ring.vrf.ring.ring_vrf import  RingVrf as RVRF


def test_all_vrfs():
    #Generate IETF Proof
    vrf = IETF_VRF(Bandersnatch_TE_Curve, BandersnatchPoint)
    secret_key="3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18"
    alpha=b""
    add=b""
    proof= vrf.proof(alpha,secret_key,add)
    print()
    print("IETF_Proof", proof.hex())

    #Verify IETF Proof
    input_point=BandersnatchPoint.encode_to_curve(alpha)
    public_key=vrf.get_public_key(secret_key)
    pub_key=BandersnatchPoint.string_to_point(public_key)
    verified= vrf.verify(pub_key,input_point,add,proof)
    print("Is IETF Proof Valid:", verified)


    #For Pedersen VRF
    #proof
    vrf = PedersenVRF(Bandersnatch_TE_Curve, BandersnatchPoint)
    proof = vrf.proof(alpha,secret_key,add)
    print("Pedersen Proof", proof.hex())

    #verfify pedersen proof
    p_proof_valid= vrf.verify(input_point, add, proof)
    print("Is Pedersen Proof Valid:", p_proof_valid)


    #Ring_VRF
    # proof generation
    pk_ring="5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede187f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e3348e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d"

    s_k="3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18"
    p_k=RVRF.get_public_key(s_k)
    alpha=b""
    ad=b""
    ring_vrf_proof= RVRF.ring_vrf_proof(alpha, ad,p_k,s_k, pk_ring)
    print("Ring_VRF_Proof:", ring_vrf_proof.hex())

    #RingVrf Proof Verify using (add, ring_root, ring_vrf_proof, message)
    RING_ROOT=RVRF.construct_ring_root(pk_ring)
    print("Is The Ring Proof Valid:", RVRF.ring_vrf_proof_verify(add, RING_ROOT, ring_vrf_proof, alpha)) #c, r,sign,alpha
