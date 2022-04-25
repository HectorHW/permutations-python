import abc
from typing import List
import itertools


class BlockCypher(abc.ABC):
    @abc.abstractmethod
    def block_size(self) -> int:
        ...

    @abc.abstractmethod
    def encrypt(self, data):
        ...


class Permutation(BlockCypher):
    def __init__(self, *indices: List[int]):
        self.indices = indices

    def encrypt(self, data):
        assert len(data) == len(self.indices)
        indices = sorted(enumerate(self.indices), key=lambda x: x[1])
        return [data[i] for i, _ in indices]

    def block_size(self) -> int:
        return len(self.indices)

    def decrypt(self, data):
        assert len(data) == len(self.indices)
        return [data[i] for i in self.indices]


class Vertical(BlockCypher):
    def __init__(self, rows: int, columns: int, permutation: Permutation):
        assert permutation.block_size() == columns
        self.rows = rows
        self.columns = columns
        self.permutation = permutation

    def block_size(self) -> int:
        return self.rows * self.columns

    def encrypt(self, data):
        assert len(data) == self.columns * self.rows
        blocks = [data[i::self.columns] for i in range(self.columns)]
        permuted = self.permutation.encrypt(blocks)
        return list(itertools.chain(*permuted))


class Railfence(BlockCypher):
    def __init__(self, rows: int, columns: int) -> None:
        self.rows = rows
        self.columns = columns

    def block_size(self) -> int:
        return self.columns

    def encrypt(self, data):
        assert len(data) == self.columns
        matrix = [[None for _ in range(self.columns)]
                  for _ in range(self.rows)]
        j = 0
        delta = 1
        for i, item in enumerate(data):
            matrix[j][i] = item
            j += delta
            if j == 0 or j == self.rows-1:
                delta *= -1
        return [item for item in itertools.chain(*matrix) if item is not None]


class Decryptor(BlockCypher):
    def __init__(self, encryptor: BlockCypher):
        self._inner = encryptor

    def block_size(self) -> int:
        return self._inner.block_size()

    def encrypt(self, data):
        return self._inner.encrypt(data)

    def decrypt(self, data):
        if hasattr(self._inner, "decrypt"):
            return self._inner.decrypt(data)
        else:
            indices = list(range(self.block_size()))
            encrypted_indices = self.encrypt(indices)
            return Permutation(*encrypted_indices).encrypt(data)
