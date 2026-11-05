"""Graph-based unimodular keys for HILLCRYPT.

A valid key is the adjacency matrix of a simple undirected graph whose
integer determinant is exactly +1 or -1. All arithmetic used for validation
and inversion is exact integer arithmetic.
"""
from __future__ import annotations

from typing import Iterable, Sequence

SUPPORTED_ORDERS = tuple(range(1, 17))
SUPPORTED_MODULI = (128, 256)


class GraphKeyError(ValueError):
    """Raised when a graph cannot be used as a unimodular Hill key."""


def _square_matrix(matrix: Sequence[Sequence[int]]) -> list[list[int]]:
    rows = [list(row) for row in matrix]
    n = len(rows)
    if n == 0 or any(len(row) != n for row in rows):
        raise GraphKeyError("Matriks harus persegi dan tidak kosong.")
    if any(not isinstance(x, int) or isinstance(x, bool) for row in rows for x in row):
        raise GraphKeyError("Semua entri matriks harus berupa bilangan bulat.")
    return rows


def determinant_bareiss(matrix: Sequence[Sequence[int]]) -> int:
    """Return exact determinant using fraction-free Bareiss elimination."""
    a = _square_matrix(matrix)
    n = len(a)
    if n == 1:
        return a[0][0]
    sign, previous_pivot = 1, 1
    for k in range(n - 1):
        if a[k][k] == 0:
            swap = next((r for r in range(k + 1, n) if a[r][k] != 0), None)
            if swap is None:
                return 0
            a[k], a[swap] = a[swap], a[k]
            sign *= -1
        pivot = a[k][k]
        for i in range(k + 1, n):
            for j in range(k + 1, n):
                numerator = a[i][j] * pivot - a[i][k] * a[k][j]
                if numerator % previous_pivot:
                    raise ArithmeticError("Pembagian Bareiss tidak eksak.")
                a[i][j] = numerator // previous_pivot
        for i in range(k + 1, n):
            a[i][k] = 0
        previous_pivot = pivot
    return sign * a[n - 1][n - 1]


def adjacency_matrix(order: int, edges: Iterable[tuple[int, int]]) -> list[list[int]]:
    """Build adjacency matrix; vertices are numbered 0..order-1."""
    if not isinstance(order, int) or isinstance(order, bool) or order < 1:
        raise GraphKeyError("Ordo graf harus bilangan bulat positif.")
    a = [[0] * order for _ in range(order)]
    seen = set()
    for edge in edges:
        if len(edge) != 2:
            raise GraphKeyError("Setiap sisi harus berupa pasangan dua simpul.")
        u, v = edge
        if not all(isinstance(x, int) and not isinstance(x, bool) for x in (u, v)):
            raise GraphKeyError("Indeks simpul harus berupa bilangan bulat.")
        if not (0 <= u < order and 0 <= v < order):
            raise GraphKeyError("Indeks simpul berada di luar rentang graf.")
        if u == v:
            raise GraphKeyError("Loop tidak diperbolehkan pada graf sederhana.")
        pair = (min(u, v), max(u, v))
        if pair in seen:
            raise GraphKeyError("Sisi duplikat tidak diperbolehkan.")
        seen.add(pair)
        a[u][v] = a[v][u] = 1
    return a


def validate_adjacency(matrix: Sequence[Sequence[int]], require_supported_order: bool = True) -> dict:
    """Validate simple undirected 0/1 adjacency matrix and unimodularity."""
    a = _square_matrix(matrix)
    n = len(a)
    if require_supported_order and n not in SUPPORTED_ORDERS:
        raise GraphKeyError(f"Ordo graf harus berada pada rentang 1 sampai 16: {SUPPORTED_ORDERS}.")
    for i in range(n):
        if a[i][i] != 0:
            raise GraphKeyError("Diagonal utama harus nol (graf tanpa loop).")
        for j in range(n):
            if a[i][j] not in (0, 1):
                raise GraphKeyError("Matriks ketetanggaan hanya boleh berisi 0 dan 1.")
            if a[i][j] != a[j][i]:
                raise GraphKeyError("Matriks harus simetris (graf tak berarah).")
    det = determinant_bareiss(a)
    return {
        "valid_graph": True,
        "order": n,
        "determinant": det,
        "unimodular": det in (-1, 1),
        "is_hill_key": det in (-1, 1),
        "reason": "Matriks ketetanggaan unimodular." if det in (-1, 1)
                  else "Determinan bukan +1 atau -1.",
    }


def path_graph(order: int) -> list[list[int]]:
    if order not in SUPPORTED_ORDERS:
        raise GraphKeyError(f"Ordo graf harus berada pada rentang 1 sampai 16: {SUPPORTED_ORDERS}.")
    return adjacency_matrix(order, ((i, i + 1) for i in range(order - 1)))


def complete_graph(order: int) -> list[list[int]]:
    """Build the complete simple undirected graph K_n."""
    if order not in SUPPORTED_ORDERS:
        raise GraphKeyError(f"Ordo graf harus berada pada rentang 1 sampai 16: {SUPPORTED_ORDERS}.")
    return adjacency_matrix(order, ((i, j) for i in range(order) for j in range(i + 1, order)))


def unique_perfect_matching_tree(order: int) -> list[list[int]]:
    """Construct a tree with a unique perfect matching, for even order >= 2."""
    if order not in SUPPORTED_ORDERS or order % 2 != 0:
        raise GraphKeyError("Pohon dengan perfect matching tunggal pada generator ini memerlukan ordo genap 2 sampai 16.")
    edges = [(0, 1)]
    next_vertex = 2
    while next_vertex < order:
        attach_to = 0
        edges.extend(((attach_to, next_vertex), (next_vertex, next_vertex + 1)))
        next_vertex += 2
    return adjacency_matrix(order, edges)


def bipartite_unimodular_graph(order: int) -> list[list[int]]:
    """Build a bipartite graph from an upper-triangular binary B with det(B)=1."""
    if order not in SUPPORTED_ORDERS or order % 2 != 0:
        raise GraphKeyError("Generator graf bipartit unimodular ini memerlukan ordo genap 2 sampai 16.")
    k = order // 2
    b = [[0] * k for _ in range(k)]
    for i in range(k):
        b[i][i] = 1
        if i + 1 < k:
            b[i][i + 1] = 1
    a = [[0] * order for _ in range(order)]
    for i in range(k):
        for j in range(k):
            a[i][k + j] = b[i][j]
            a[k + j][i] = b[i][j]
    return a


def derive_graph_passphrase(matrix: Sequence[Sequence[int]]) -> str:
    """Create a deterministic passphrase from a validated adjacency matrix.

    The passphrase is a SHA-256 fingerprint of the graph order and its
    canonical row-major adjacency entries. Identical labeled adjacency
    matrices produce the same passphrase.
    """
    import hashlib

    a = _square_matrix(matrix)
    report = validate_adjacency(a)
    if not report["is_hill_key"]:
        raise GraphKeyError("Graf belum memenuhi syarat determinan +1 atau -1.")
    canonical = "HILLCRYPT-GRAPH-KEY-v1|" + str(len(a)) + "|" + ";".join(
        ",".join(str(value) for value in row) for row in a
    )
    digest = hashlib.sha256(canonical.encode("ascii")).hexdigest().upper()
    return "GKL1-" + digest


def inverse_integer_unimodular(matrix: Sequence[Sequence[int]]) -> list[list[int]]:
    """Compute exact integer inverse for a matrix with determinant +/-1."""
    a = _square_matrix(matrix)
    det = determinant_bareiss(a)
    if det not in (-1, 1):
        raise GraphKeyError("Invers hanya tersedia jika determinan tepat +1 atau -1.")
    n = len(a)
    if n == 1:
        return [[det * a[0][0]]]
    cofactors = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            minor = [row[:j] + row[j + 1:] for r, row in enumerate(a) if r != i]
            cofactors[i][j] = ((-1) ** (i + j)) * determinant_bareiss(minor)
    return [[cofactors[j][i] // det for j in range(n)] for i in range(n)]


def inverse_mod(matrix: Sequence[Sequence[int]], modulus: int) -> list[list[int]]:
    if not isinstance(modulus, int) or isinstance(modulus, bool) or modulus < 2:
        raise GraphKeyError("Modulus harus bilangan bulat minimal 2.")
    inv = inverse_integer_unimodular(matrix)
    return [[x % modulus for x in row] for row in inv]


def multiply_matrix_vector_mod(matrix: Sequence[Sequence[int]], vector: Sequence[int],
                               modulus: int) -> list[int]:
    a = _square_matrix(matrix)
    if len(vector) != len(a):
        raise GraphKeyError("Panjang vektor harus sama dengan ordo matriks.")
    if modulus < 2:
        raise GraphKeyError("Modulus minimal 2.")
    return [sum(a[i][j] * int(vector[j]) for j in range(len(a))) % modulus
            for i in range(len(a))]


def encrypt_bytes(data: bytes, key_matrix: Sequence[Sequence[int]],
                  modulus: int = 256) -> tuple[bytes, int]:
    """Encrypt bytes in column blocks; zero-pad and return original byte length."""
    a = _square_matrix(key_matrix)
    report = validate_adjacency(a)
    if not report["is_hill_key"]:
        raise GraphKeyError("Kunci graf harus memiliki determinan +1 atau -1.")
    if modulus not in SUPPORTED_MODULI:
        raise GraphKeyError(f"Modulus yang didukung: {SUPPORTED_MODULI}.")
    if any(value >= modulus for value in data):
        raise GraphKeyError("Ada byte plaintext di luar rentang modulus yang dipilih.")
    n = len(a)
    padded = data + bytes((-len(data)) % n)
    out = bytearray()
    for start in range(0, len(padded), n):
        out.extend(multiply_matrix_vector_mod(a, padded[start:start+n], modulus))
    return bytes(out), len(data)


def decrypt_bytes(ciphertext: bytes, key_matrix: Sequence[Sequence[int]],
                  original_length: int, modulus: int = 256) -> bytes:
    a = _square_matrix(key_matrix)
    report = validate_adjacency(a)
    if not report["is_hill_key"]:
        raise GraphKeyError("Kunci graf harus memiliki determinan +1 atau -1.")
    if modulus not in SUPPORTED_MODULI:
        raise GraphKeyError(f"Modulus yang didukung: {SUPPORTED_MODULI}.")
    if any(value >= modulus for value in ciphertext):
        raise GraphKeyError("Ada byte ciphertext di luar rentang modulus yang dipilih.")
    n = len(a)
    if len(ciphertext) % n:
        raise GraphKeyError("Panjang ciphertext harus kelipatan ordo matriks.")
    if not isinstance(original_length, int) or not 0 <= original_length <= len(ciphertext):
        raise GraphKeyError("Panjang byte asli tidak valid.")
    inv = inverse_mod(a, modulus)
    out = bytearray()
    for start in range(0, len(ciphertext), n):
        out.extend(multiply_matrix_vector_mod(inv, ciphertext[start:start+n], modulus))
    return bytes(out[:original_length])
