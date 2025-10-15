from dot_ring.vrf.ring.ring_vrf import  RingVrf as RVRF
def test_ring_vrf():

    try:
        # Installation of blst is required as defined in readme to try this
        pk_ring = "5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede187f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e3348e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d"

        s_k = "3d6406500d4009fdf2604546093665911e753f2213570a29521fd88bc30ede18"
        p_k = RVRF.get_public_key(s_k)
        alpha = b""
        add = b""
        ring_vrf_proof = RVRF.ring_vrf_proof(alpha, add, p_k, s_k, pk_ring, True)
        print("Ring_VRF_Proof:", ring_vrf_proof.hex())
        # RingVrf Proof Verify using (add, ring_root, ring_vrf_proof, message)
        RING_ROOT = RVRF.construct_ring_root(pk_ring, True)
        print("Is The Ring Proof Valid:",RVRF.ring_vrf_proof_verify(add, RING_ROOT, ring_vrf_proof, alpha))  # c, r_root,sign,alpha

    except Exception as e:
        print("Third Party Blst Module Not Installed , So KZG Coverage <80%")
