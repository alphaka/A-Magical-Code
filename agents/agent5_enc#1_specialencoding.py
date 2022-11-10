import math
import random
from collections import Counter

class Node:
    def __init__(self, left=None, right=None):
        self.left = left
        self.right = right

    def children(self):
        return self.left, self.right
    
def huffman_code(node, bin_str=''):
    if type(node) is str:
        return {node : bin_str}
    l, r = node.children()
    _dict = dict()
    _dict.update(huffman_code(l, bin_str + '0'))
    _dict.update(huffman_code(r, bin_str + '1'))
    return _dict

def make_tree(nodes):
    """
    make tree buils the huffman tree and returns the root of the tree
    """
    while len(nodes) > 1:
        
        k1, v1 = nodes[-1]
        k2, v2 = nodes[-2]
        nodes = nodes[:-2] # saves the whole
        combined_node = Node(k1, k2)
        nodes.append((combined_node, v1 + v2))
        nodes = sorted(nodes, key=lambda x : x[1], reverse=True)
    return nodes[0][0] # root


class ASCII_Frequencies:
    """
    - Lowercase frequencies https://en.wikipedia.org/wiki/Letter_frequency
    - Uppercases frequencies https://link.springer.com/article/10.3758/BF03195586
    - Letters and numbers frequencies uses the above two sources and normalized the data
        * assumption for the above words, length of an average english word is 4.7
    - For all printable ascii values, we use https://github.com/piersy/ascii-char-frequency-english
    """

    alphabet = {
       'e': 0.11322102704553863,
 't': 0.08323232612835182,
 'a': 0.08054836681705162,
 'n': 0.07237147137028112,
 'i': 0.07206801219404152,
 'o': 0.0712582320906787,
 's': 0.06822864102879744,
 'r': 0.067753324444866,
 'l': 0.04231792803641911,
 'd': 0.04193337416683121,
 'h': 0.03444190807062223,
 'c': 0.032877522259576526,
 'u': 0.025310045515542633,
 'm': 0.023853591490607978,
 'p': 0.022830448165280487,
 'f': 0.02071106794210089,
 'g': 0.016837608668347624,
 'y': 0.014324756659662074,
 'b': 0.01360515585558277,
 'w': 0.012578678729912082,
 'v': 0.010281856983465768,
 'k': 0.006503411019493648,
 'S': 0.004062819133246916,
 'T': 0.0040370655255957105,
 'C': 0.003928300289398874,
 'A': 0.00325778969537316,
 'x': 0.00303284151721587,
 'I': 0.0027496351780611932,
 '-': 0.0027307992061221245,
 'M': 0.0023846673854895843,
 'B': 0.0022863202753652407,
 "'": 0.001982777754117056,
 'P': 0.0018265892080382262,
 'E': 0.0017013216601425582,
 'N': 0.001677735022714432,
 'F': 0.001604641450189814,
 'R': 0.0014513699794112824,
 'D': 0.001436951292926951,
 'U': 0.0013710253911402089,
 'q': 0.0013261857765241947,
 'L': 0.0013208516959750778,
 'G': 0.0012242548310309135,
 'J': 0.0011590790343213911,
 'H': 0.0011509112234805558,
 'O': 0.0010796512411446971,
 'W': 0.0010583149189482292,
 'j': 0.0008121137636030513,
 'z': 0.0007577728180089227,
 'K': 0.0005007368115483511,
 'V': 0.00033613041960294605,
 'Y': 0.00033129640910530884,
 'Q': 0.00013151842353916412,
 'Z': 0.00011334921166873458,
 'X': 8.642877389741014e-05
    }

encodings = {
    'printable': ASCII_Frequencies.alphabet,
}

def generate_huffman_code(type):
    _freq = sorted(encodings[type].items(), key = lambda x : x[1], reverse=True)
    node = make_tree(_freq)
    return huffman_code(node)

# HUFFMAN ENCODING FOR VARIETY OF WORDS
# LOWERCASE_HUFFMAN = generate_huffman_code('lower')
# AIRPORT_HUFFMAN = generate_huffman_code('airport')
# PASSPORT_HUFFMAN = generate_huffman_code('password')
# LOCATION_HUFFMAN = generate_huffman_code('location')
# ADDRESS_HUFFMAN = generate_huffman_code('address')
PRINTTABLE_HUFFMAN = generate_huffman_code('printable')
# NUMBER_HUFFMAN = generate_huffman_code('number')
# LETTERS_HUFFMAN = generate_huffman_code('letters')

def encode_msg_bin(msg, encoding) -> str:
    """
    takes a string and returns a binary encoding of each letter per 'encoding'
    """

    binaries = []
    for letter in msg:
        binaries.append(encoding[letter])
    return "".join(binaries)

def decode_bin_msg(msg, encoding) -> str:
    """
    takes a binary str and decodes the message according to 'encoding'
    """
    output = ''
    while msg:
        found_match = False
        for ch, binary in encoding.items():
            if msg.startswith(binary):
                found_match = True
                output += ch
                msg = msg[len(binary):]
        if not found_match:
            break # break and returns partial msg
    return output

def bin_to_cards(msg_bin):
    """
    takes a binary string and encodes the string into cards
    """
    digit = int(msg_bin, 2)
    #digit = 16
    m = digit

    min_cards = math.inf
    for i in range(1, 53):
        fact = math.factorial(i) - 1
        if digit < fact:
            min_cards = i
            break
    #print(min_cards)
    permutations = []
    elements = []
    for i in range(min_cards):
        elements.append(i)
        permutations.append(0)
    for i in range(min_cards):
        index = m % (min_cards-i)
        #print(index)
        m = m // (min_cards-i)
        permutations[i] = elements[index]
        elements[index] = elements[min_cards-i-1]

    remaining_cards = []
    for i in range(min_cards, 52):
        remaining_cards.append(i)

    random.shuffle(remaining_cards)

    # print("permutation is ", permutations)
    returned_list = remaining_cards + permutations

   # print(permutations)
   # print(returned_list)


    return returned_list

def cards_to_bin(cards):
    """
    takes a binary string and encodes the string into cards
    """
    m = 1
    digit = 0
    length = len(cards)
    positions = []
    elements = []
    for i in range(length):
        positions.append(i)
        elements.append(i)

    for i in range(length-1):
        digit += m * positions[cards[i]]
        m = m * (length - i)
        positions[elements[length-i-1]] = positions[cards[i]]
        elements[positions[cards[i]]] = elements[length-i-1]
     
    return format(digit, 'b')

class Agent:

    def __init__(self):
       self.scheme_id_to_encoding = { "001": PRINTTABLE_HUFFMAN
                                    }

       self.encoding_to_scheme_id = { "PRINTTABLE_HUFFMAN" : "001"
                                    }
        #self.encoding = huffman_code(node)
        
    def compute_crc8_checksum(self, data) -> str:
        # data is a binary string
        # we would like to turn it into a list of bytes
        # then compute the crc and return the crc as a binary string
        if len(data) % 8 != 0:
            data = "0" * (8 - len(data) % 8) + data
        
        byte_list = [int(data[i:i+8], 2) for i in range(0, len(data), 8)]
        generator = 0x9B
        crc = 0
        for curr_byte in byte_list:
            crc ^= curr_byte
            # mask to trim to 8 bits
            crc &= 0xFF
            for i in range(8):
                if crc & 0x80 != 0:
                    crc = (crc << 1) ^ generator
                    # mask to trim to 8 bits
                    crc &= 0xFF
                else:
                    crc = crc << 1
        return format(crc, '08b')

    def compute_crc16_checksum(self, data) -> str:
        if len(data) % 8 != 0:
            data = "0" * (8 - len(data) % 8) + data
        
        byte_list = [int(data[i:i+8], 2) for i in range(0, len(data), 8)]
        # polynomial generator picked based on https://users.ece.cmu.edu/~koopman/crc/
        generator = 0xED2F
        crc = 0
        for curr_byte in byte_list:
            crc ^= (curr_byte << 8)
            # mask to trim to 16 bits
            crc &= 0xFFFF
            for i in range(8):
                if crc & 0x8000 != 0:
                    crc = (crc << 1) ^ generator
                    # mask to trim to 16 bits
                    crc &= 0xFFFF
                else:
                    crc = crc << 1
        return format(crc, '016b')

        

    def encode(self, message):
        """
        FYI: use 'encode_msg_bin' to compress a message to binary
        """
        ms = set(message)
        
        encoding = PRINTTABLE_HUFFMAN
        scheme_id = self.encoding_to_scheme_id["PRINTTABLE_HUFFMAN"]
        
        msg_huffman_binary = encode_msg_bin(message, encoding)
       
        #print("encoded scheme id is ", scheme_id)
        
        
        # Calculate checksum before prepending the leading 1 bit
        # assert(len(self.compute_crc16_checksum(msg_huffman_binary)) == 16)
        msg_huffman_binary += self.compute_crc16_checksum(msg_huffman_binary)

        # Appending 3-bit identifier for encoding scheme
        msg_huffman_binary += scheme_id
        
        msg_huffman_binary = "1" + msg_huffman_binary
        
        cards = bin_to_cards(msg_huffman_binary)
        
        return cards



    def decode(self, deck):
        """
        Given a binary str, use 'decode_bin_msg' to decode it
        see main below
        """
        #print("after shuffling ", deck)
      
        for perm_bound in range(1, 52):
            msg_cards = []
            for c in deck:
                if c <= perm_bound:
                    msg_cards.append(c)
            bin_raw = cards_to_bin(msg_cards)
            bin_raw = bin_raw[1:] # remove leading 1
            bin_message, tail = bin_raw[:-19], bin_raw[-19:]
            checksum, scheme_id = tail[:-3], tail[-3:]

            if scheme_id in self.scheme_id_to_encoding and checksum == self.compute_crc16_checksum(bin_message):
               #print("scheme_id ", scheme_id)
               decoded_message = decode_bin_msg(bin_message, self.scheme_id_to_encoding[scheme_id])
               return decoded_message
        return "NULL"


if __name__=='__main__':
    agent = Agent()
    encoded = agent.encode('abcd')
    #print("ENCODED: ", encoded)
    decoded = agent.decode(encoded)
    print('Encoded msg: ', encoded)
    print('Decoded msg: ', decoded)
    
    