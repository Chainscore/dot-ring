"""Additional tests for transcript module to improve coverage."""

from dot_ring.ring_proof.constants import S_PRIME
from dot_ring.ring_proof.transcript.transcript import Transcript


class TestTranscriptAdditional:
    """Additional tests for Transcript class."""

    def test_transcript_init(self):
        """Test Transcript initialization."""
        transcript = Transcript(S_PRIME, b"test_transcript")
        assert transcript is not None

    def test_transcript_label(self):
        """Test adding label to transcript."""
        transcript = Transcript(S_PRIME, b"test")
        transcript.label(b"new_label")
        # Just verify it doesn't error

    def test_transcript_write(self):
        """Test writing data to transcript."""
        transcript = Transcript(S_PRIME, b"test")
        transcript.write(b"some_data")
        # Just verify it doesn't error

    def test_transcript_write_bytes(self):
        """Test writing bytes to transcript."""
        transcript = Transcript(S_PRIME, b"test")
        transcript.write_bytes(b"more_data_here")
        # Just verify it doesn't error

    def test_transcript_append(self):
        """Test appending data to transcript."""
        transcript = Transcript(S_PRIME, b"test")
        transcript.append(b"appended_data")
        # Just verify it doesn't error

    def test_transcript_add_serialized(self):
        """Test add_serialized method."""
        transcript = Transcript(S_PRIME, b"test")
        transcript.add_serialized(b"label", b"serialized_data")
        # Just verify it doesn't error

    def test_transcript_challenge(self):
        """Test getting challenge."""
        transcript = Transcript(S_PRIME, b"test")
        transcript.append(b"some_data")

        challenge = transcript.challenge(b"challenge")

        assert isinstance(challenge, int)
        assert 0 <= challenge < S_PRIME

    def test_transcript_read_reduce(self):
        """Test read_reduce method."""
        transcript = Transcript(S_PRIME, b"test")
        transcript.write(b"data")

        result = transcript.read_reduce()

        assert isinstance(result, int)
        assert 0 <= result < S_PRIME

    def test_transcript_separate(self):
        """Test separate method."""
        transcript = Transcript(S_PRIME, b"test")
        transcript.write(b"data1")
        transcript.separate()
        transcript.write(b"data2")
        # Just verify it doesn't error

    def test_transcript_get_constraints_aggregation_coeffs(self):
        """Test getting constraint aggregation coefficients."""
        transcript = Transcript(S_PRIME, b"test")

        coeffs = transcript.get_constraints_aggregation_coeffs(3)

        assert len(coeffs) == 3
        for c in coeffs:
            assert isinstance(c, int)
            assert 0 <= c < S_PRIME

    def test_transcript_get_evaluation_point(self):
        """Test getting evaluation point."""
        transcript = Transcript(S_PRIME, b"test")

        points = transcript.get_evaluation_point(1)

        assert len(points) == 1
        assert isinstance(points[0], int)

    def test_transcript_get_kzg_aggregation_challenges(self):
        """Test getting KZG aggregation challenges."""
        transcript = Transcript(S_PRIME, b"test")

        challenges = transcript.get_kzg_aggregation_challenges(5)

        assert len(challenges) == 5
        for c in challenges:
            assert isinstance(c, int)
            assert 0 <= c < S_PRIME

    def test_transcript_large_write(self):
        """Test writing large data (>2^31 bytes would trigger chunking)."""
        transcript = Transcript(S_PRIME, b"test")
        # Write 100KB of data
        large_data = b"x" * 100000
        transcript.write_bytes(large_data)
        # Just verify it doesn't error
