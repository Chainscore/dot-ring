#create the ring vrf class and put in the signature generation and verification logics

from typing import List

from dot_ring.ring_proof.gotos import*

class RingVrf:

    @staticmethod
    def generate_bls_signature(secret_t:bytes|str,producer_key:bytes|str, keys: List[Any], third_party_msm:bool=False)->bytes:
        """
            get the all the data needed and
            return the signature as an output"
            """
        return generate_bls_signature(secret_t, producer_key, keys, third_party_msm)

    @staticmethod
    def construct_ring_root(keys: List[Any], third_party_msm:bool=False)->bytes:
        """
        get the data needed and construct the rng root
        """
        return construct_ring_root(keys, third_party_msm)

    @staticmethod
    def verify_signature(message:bytes|str,ring_root:bytes|str, ring_signature:bytes|str)->bool:
        """
        get the bls signature, other params if needed and verify it
        """
        return verify_signature(message,ring_root, ring_signature)

    @staticmethod
    def ring_vrf_proof(alpha:bytes|str, add:bytes|str, blinding_factor:bytes|str, secret_key:bytes|str, producer_key:bytes|str, keys:List[Any], third_party_msm:bool=False)->bytes:
        """get the args u want and generate the
        ring_vrf_proof (pedersen vrf proof + ring_proof ) \
        which of length 784 bytes"""
        return ring_vrf_proof(alpha, add, blinding_factor, secret_key,producer_key, keys, third_party_msm)

    @staticmethod
    def ring_vrf_proof_verify(ad_data:bytes|str, ring_root:bytes|str, signature:bytes|str, message:bytes|str=b"")->bool:
        """get the c, r, signature, m and verify the signature"""
        #verfify the signature (pedersen_proof+ring_proof)
        return ring_vrf_proof_verify(ad_data, ring_root, signature)

    @staticmethod
    def pedersen_proof_to_hash(pedersen_proof:bytes|str)->bytes:
        """get the pedersen proof alone and return the 32 bytes hash"""
        return pedersen_proof_to_hash(pedersen_proof)
