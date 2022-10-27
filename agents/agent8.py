import heapq
from math import factorial, log2
from pprint import pprint
from random import Random
from typing import Optional


# ================
# Message <-> Bits
# ================
class FreqTree:
    char: Optional[str]
    freq: float
    left: Optional["FreqTree"]
    right: Optional["FreqTree"]

    def __init__(self, char: Optional[str], freq: float):
        self.char = char
        self.freq = freq
        self.left = None
        self.right = None

    def __lt__(self, other: "FreqTree"):
        return self.freq < other.freq

    def __eq__(self, other: "FreqTree"):
        return self.freq == other.freq


def make_huffman_encoding(frequencies: dict[str, float]) -> dict[str, str]:
    """
    frequencies is a dictionary mapping from a character in the English alphabet to its frequency.
    Returns a dictionary mapping from a character to its Huffman encoding.
    """
    huffman_encoding: dict[str, str] = {}
    heap: list[FreqTree] = []

    for char, freq in frequencies.items():
        heapq.heappush(heap, FreqTree(char, freq))

    while len(heap) > 1:
        left = heapq.heappop(heap)
        right = heapq.heappop(heap)
        node = FreqTree(None, left.freq + right.freq)
        node.left = left
        node.right = right
        heapq.heappush(heap, node)

    root = heapq.heappop(heap)

    def traverse(node, encoding):
        if node.char:
            huffman_encoding[node.char] = encoding
        else:
            traverse(node.left, encoding + "0")
            traverse(node.right, encoding + "1")

    traverse(root, "")

    return huffman_encoding


def huffman_encode_message(message: str, encoding: dict[str, str]):
    """
    Encodes a message using the given encoding.
    """
    processed_message = message.replace(" ", "")

    encoded_message = []
    for char in processed_message:
        encoded_message.append(encoding[char])
    return "".join(encoded_message)


def huffman_decode_message(encoded_message: str, encoding: dict[str, str]):
    """
    Decodes a message using the given encoding.
    """
    decoded_message = ""
    while encoded_message:
        dead = True
        for char, code in encoding.items():
            if encoded_message.startswith(code):
                dead = False
                decoded_message += char
                encoded_message = encoded_message[len(code) :]
        if dead:
            break
    return decoded_message


# ==============
# Bits <-> Cards
# ==============
def bottom_cards_encode(value: int, n: int) -> list[int]:
    if value >= factorial(n):
        raise ValueError(f"{value} is too large to encode in {n} cards!")

    cards = []
    current_value = 0
    digits = list(range(n))
    for i in range(n):
        # First n bins of (n-1)!, then n-1 bins of (n-2)!, and so on bin_width = factorial(n - i) // (n - i)
        bin_width = factorial(n - i) // (n - i)
        # Target value falls into one of these bins
        bin_no = (value - current_value) // bin_width
        # Of the cards still available, ordered by value, select the bin_no'th largest
        card_value = digits[bin_no]
        # Once a card has been used, it can't be used again
        digits = [digit for digit in digits if digit != card_value]
        cards.append(card_value)
        # Move to the bottom of the current bin
        current_value += bin_no * bin_width

    return cards


def bottom_cards_decode(cards: list[int], n: int) -> int:
    cards = [card for card in cards if card < n]
    # Assuming the top card is the first card in the list
    lo = 0
    hi = factorial(n)
    digits = list(range(n))
    for i in range(n):
        card_value = cards[i]
        # Range will always be divisible by the place value
        bin_width = (hi - lo) // (n - i)
        bin_no = digits.index(card_value)
        lo = lo + bin_no * bin_width
        hi = lo + bin_width
        digits = [digit for digit in digits if digit != card_value]

    return lo


def find_n_for_message(bits: list[int]) -> int:
    # In practice, with an 8 bits checksum, this value is always > 5,
    for n in range(1, 52):
        if int(log2(factorial(n))) >= len(bits):
            return n
    return 0


def to_bit_list(value: int) -> list[int]:
    """255 -> [1, 1, 1, 1, 1, 1, 1, 1]"""
    return [int(bit) for bit in bin(value)[2:]]


def from_bit_list(bits: list[int]) -> int:
    """[1, 1, 1, 1, 1, 1, 1, 1] -> 255"""
    return int("0b" + "".join(map(str, bits)), 2)


# ===================
# Checksum Algorithms
# ===================
def quarter_sum_checksum(sent_message: str) -> str:
    k = int(((len(sent_message) / 4) + 1) // 1)

    # Dividing sent message in packets of k bits.
    c1 = sent_message[0:k]
    c2 = sent_message[k : 2 * k]
    c3 = sent_message[2 * k : 3 * k]
    c4 = sent_message[3 * k : 4 * k]

    # Calculating the binary sum of packets
    sum = bin(int(c1, 2) + int(c2, 2) + int(c3, 2) + int(c4, 2))[2:]

    # Adding the overflow bits
    if len(sum) > k:
        x = len(sum) - k
        sum = bin(int(sum[0:x], 2) + int(sum[x:], 2))[2:]
    if len(sum) < k:
        sum = "0" * (k - len(sum)) + sum

    # Calculating the complement of sum
    checksum = ""
    for i in sum:
        if i == "1":
            checksum += "0"
        else:
            checksum += "1"
    return checksum


# Create separate random instance with constant seed
# so that the pearson_table is always the same
random = Random(0)
pearson_table = list(range(256))
random.shuffle(pearson_table)


def pearson_checksum(bits: list[int]) -> int:
    checksum = 0
    for off in range(0, len(bits), 8):
        byte = bits[off : off + 8]
        byte_val = from_bit_list(byte)
        checksum = pearson_table[checksum ^ byte_val]
    return checksum


def add_checksum(bits: list[int]) -> list[int]:
    padding = 8 - (len(bits) % 8)
    padded_bits = [0] * padding + bits
    checksum = pearson_checksum(padded_bits)
    checksum_bits = to_bit_list(checksum)
    padded_checksum = [0] * (8 - len(checksum_bits)) + checksum_bits
    return padded_bits + padded_checksum
    # checksum = findChecksum("".join(map(str, bits)))
    # return bits + [int(bit) for bit in checksum]


def check_and_remove(bits: list[int]) -> tuple[bool, list[int]]:
    message_length = from_bit_list(bits[-8:])
    message_checksum = bits[-16:-8]
    message = bits[:-16]
    print("message length", message_length)
    # print("checksum", checksum)
    message = [0] * (message_length - len(message)) + message
    print("decoded message bits", message)
    # message = ([0] * 100 + bits)[-(message_length + 16) : -16]
    # checked_checksum = findChecksum("".join(map(str, message)))

    padding = 8 - (len(message) % 8)
    padded_bits = [0] * padding + message
    checksum = pearson_checksum(padded_bits)
    checksum_bits = to_bit_list(checksum)
    checked_checksum = [0] * (8 - len(checksum_bits)) + checksum_bits

    print("checked_checksum", checked_checksum)
    # same = True
    # for checksum_bit in range(8):
    #     if checksum[checksum_bit] != checked_checksum[checksum_bit]:
    #         same = False
    return checked_checksum == message_checksum, message
    # message_checksum = bits[-8:]
    # message = bits[:-8]
    # checked_checksum = pearson_checksum(message)
    # return message_checksum == checked_checksum, message


def length_byte(bits: list[int]) -> list[int]:
    length_bits = to_bit_list(len(bits))
    return [0] * (8 - len(length_bits)) + length_bits


class Agent:
    def __init__(self):
        # Source for frequencies: http://mathcenter.oxford.emory.edu/site/math125/englishLetterFreqs/
        self.frequencies = {
            "a": 0.08167,
            "b": 0.01492,
            "c": 0.02782,
            "d": 0.04253,
            "e": 0.12702,
            "f": 0.02228,
            "g": 0.02015,
            "h": 0.06094,
            "i": 0.06966,
            "j": 0.00153,
            "k": 0.00772,
            "l": 0.04025,
            "m": 0.02406,
            "n": 0.06749,
            "o": 0.07507,
            "p": 0.01929,
            "q": 0.00095,
            "r": 0.05987,
            "s": 0.06327,
            "t": 0.09056,
            "u": 0.02758,
            "v": 0.00978,
            "w": 0.02360,
            "x": 0.00150,
            "y": 0.01974,
            "z": 0.00074,
        }
        self.encoding = make_huffman_encoding(self.frequencies)

    def encode(self, message):
        print("Message to encode:", message)
        huffman_coded = huffman_encode_message(message, self.encoding)

        bits = [int(bit) for bit in huffman_coded]
        print("Message bits", bits)

        message_length = length_byte(bits)
        # print("Message:    ", bits)
        with_checksum = add_checksum(bits)
        # print("W/ Checksum:", with_checksum)
        with_length = with_checksum + message_length
        print("W/ Length   ", with_length)

        n = find_n_for_message(with_length)
        print("n:          ", n)
        encoded = bottom_cards_encode(from_bit_list(with_length), n)
        print("As cards:", encoded)
        return list(range(n, 52)) + encoded

    def decode(self, deck):
        print(deck)
        for n in range(52):
            encoded = [card for card in deck if card < n]
            decoded = to_bit_list(bottom_cards_decode(encoded, n))
            # print("Raw decoded", decoded)
            passes_checksum, message = check_and_remove(decoded)
            print(passes_checksum, message)
            if passes_checksum:
                # print("Passes:     ", passes_checksum)
                # print("Decoded:    ", message)
                out_message = huffman_decode_message(
                    "".join(map(str, message)), self.encoding
                )
                # print("Message:    ", out_message)
                return out_message
        return "NULL"


if __name__ == "__main__":
    agent = Agent()
    pprint(agent.encoding)

    for n in range(1, 52):
        assert (
            bottom_cards_decode(bottom_cards_encode(factorial(n) - 1, n), n)
            == factorial(n) - 1
        )
        assert (
            bottom_cards_decode(bottom_cards_encode(factorial(n) // 2, n), n)
            == factorial(n) // 2
        )
        assert bottom_cards_decode(bottom_cards_encode(0, n), n) == 0
