
import pytest
from cyphers import Decryptor, PaddingCypher, Permutation, Railfence, UnpaddingCypher, Vertical


def test_permutation_should_encrypt_data():
    permutation = Permutation(1, 3, 0, 2)
    assert "".join(permutation.encrypt("abcd")) == "cadb"


def test_permutation_should_decrypt_data():
    permutation = Permutation(1, 3, 0, 2)
    assert "".join(permutation.decrypt("cadb")) == "abcd"


def test_vertical_should_permute_data():
    vertical = Vertical(2, 4, Permutation(0, 1, 2, 3))
    assert "".join(vertical.encrypt("abcdefgh")) == "aebfcgdh"


def test_vertical_should_encrypt_data():
    vertical = Vertical(2, 4, Permutation(1, 3, 0, 2))
    assert "".join(vertical.encrypt("abcdefgh")) == "cgaedhbf"


def test_railfence_should_encrypt():
    railfence = Railfence(3, 8)
    assert "".join(railfence.encrypt("abcdefgh")) == "aebdfhcg"


def test_decryptor_should_work_with_permutation():
    cypher = Decryptor(Permutation(1, 3, 0, 2))
    assert cypher.decrypt(cypher.encrypt("abcd")) == list("abcd")


def test_decryptor_should_work_with_railfence():
    cypher = Decryptor(Railfence(3, 8))
    data = "abcdefgh"
    assert cypher.decrypt(cypher.encrypt(data)) == list(data)


def test_decryptor_should_work_with_vertical():
    cypher = Decryptor(Vertical(2, 4, Permutation(0, 1, 2, 3)))
    data = "abcdefgh"
    assert cypher.decrypt(cypher.encrypt(data)) == list(data)


@pytest.fixture
def padding_permutation():
    return PaddingCypher(Permutation(1, 3, 0, 2))


def test_padding_should_encrypt_matching_size(padding_permutation):
    assert padding_permutation.encrypt("abcdefgh") == (list("cadbgehf"), 8)


def test_padding_should_add_nones(padding_permutation):
    assert padding_permutation.encrypt("abcdef") == (
        ['c', 'a', 'd', 'b', None, 'e', None, 'f'], 6)


def test_padding_should_decrypt(padding_permutation):
    assert padding_permutation.decrypt(list("cadbgehf"), 8) == list("abcdefgh")


def test_padding_should_remove_pad_values(padding_permutation):
    assert padding_permutation.decrypt(
        ['c', 'a', 'd', 'b', None, 'e', None, 'f'], 6) == list("abcdef")


@pytest.fixture
def unpadding_permutation(padding_permutation):
    return UnpaddingCypher(padding_permutation)


def test_unpadding_encryption_should_work_for_matching_size(unpadding_permutation):
    assert unpadding_permutation.encrypt("abcdefgh") == list("cadbgehf")


def test_unpadding_encryption_should_work_for_unmatching_size(unpadding_permutation):
    assert unpadding_permutation.encrypt(
        "abcdef") == ['c', 'a', 'd', 'b', 'e', 'f']


@pytest.mark.parametrize("data", ["abcdef", "abcdefg", "abc", "abcdefgh"])
def test_unpadding_should_decrypt(unpadding_permutation, data):
    encrypted = unpadding_permutation.encrypt(data)
    assert unpadding_permutation.decrypt(encrypted) == list(data)
