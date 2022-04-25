from re import L
from cyphers import Decryptor, Permutation, Railfence, Vertical


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
