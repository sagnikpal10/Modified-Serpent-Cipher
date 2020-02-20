import socket
import string
import base64
import struct
import binascii


bin2asc = {'0000000': '\x00', '0000001': '\x01', '0000010': '\x02', '0000011': '\x03', '0000100': '\x04', '0000101': '\x05',
           '0000110': '\x06', '0000111': '\x07', '0001000': '\x08', '0001001': '\t', '0001010': '\n', '0001011': '\x0b', '0001100': '\x0c',
           '0001101': '\r', '0001110': '\x0e', '0001111': '\x0f', '0010000': '\x10', '0010001': '\x11', '0010010': '\x12', '0010011': '\x13',
           '0010100': '\x14', '0010101': '\x15', '0010110': '\x16', '0010111': '\x17', '0011000': '\x18', '0011001': '\x19', '0011010': '\x1a',
           '0011011': '\x1b', '0011100': '\x1c', '0011101': '\x1d', '0011110': '\x1e', '0011111': '\x1f', '0100000': ' ', '0100001': '!',
           '0100010': '"', '0100011': '#', '0100100': '$', '0100101': '%', '0100110': '&', '0100111': "'", '0101000': '(', '0101001': ')',
           '0101010': '*', '0101011': '+', '0101100': ',', '0101101': '-', '0101110': '.', '0101111': '/', '0110000': '0', '0110001': '1',
           '0110010': '2', '0110011': '3', '0110100': '4', '0110101': '5', '0110110': '6', '0110111': '7', '0111000': '8', '0111001': '9',
           '0111010': ':', '0111011': ';', '0111100': '<', '0111101': '=', '0111110': '>', '0111111': '?', '1000000': '@', '1000001': 'A',
           '1000010': 'B', '1000011': 'C', '1000100': 'D', '1000101': 'E', '1000110': 'F', '1000111': 'G', '1001000': 'H', '1001001': 'I',
           '1001010': 'J', '1001011': 'K', '1001100': 'L', '1001101': 'M', '1001110': 'N', '1001111': 'O', '1010000': 'P', '1010001': 'Q',
           '1010010': 'R', '1010011': 'S', '1010100': 'T', '1010101': 'U', '1010110': 'V', '1010111': 'W', '1011000': 'X', '1011001': 'Y',
           '1011010': 'Z', '1011011': '[', '1011100': '\\', '1011101': ']', '1011110': '^', '1011111': '_', '1100000': '`', '1100001': 'a',
           '1100010': 'b', '1100011': 'c', '1100100': 'd', '1100101': 'e', '1100110': 'f', '1100111': 'g', '1101000': 'h', '1101001': 'i',
           '1101010': 'j', '1101011': 'k', '1101100': 'l', '1101101': 'm', '1101110': 'n', '1101111': 'o', '1110000': 'p', '1110001': 'q',
           '1110010': 'r', '1110011': 's', '1110100': 't', '1110101': 'u', '1110110': 'v', '1110111': 'w', '1111000': 'x', '1111001': 'y',
           '1111010': 'z', '1111011': '{', '1111100': '|', '1111101': '}', '1111110': '~', '1111111': '\x7f'}

asc2bin = {'\x00': '0000000', '\x01': '0000001', '\x02': '0000010', '\x03': '0000011', '\x04': '0000100', '\x05': '0000101', '\x06': '0000110',
           '\x07': '0000111', '\x08': '0001000', '\t': '0001001', '\n': '0001010', '\x0b': '0001011', '\x0c': '0001100', '\r': '0001101',
           '\x0e': '0001110', '\x0f': '0001111', '\x10': '0010000', '\x11': '0010001', '\x12': '0010010', '\x13': '0010011', '\x14': '0010100',
           '\x15': '0010101', '\x16': '0010110', '\x17': '0010111', '\x18': '0011000', '\x19': '0011001', '\x1a': '0011010', '\x1b': '0011011',
           '\x1c': '0011100', '\x1d': '0011101', '\x1e': '0011110', '\x1f': '0011111', ' ': '0100000', '!': '0100001', '"': '0100010',
           '#': '0100011', '$': '0100100', '%': '0100101', '&': '0100110', "'": '0100111', '(': '0101000', ')': '0101001', '*': '0101010',
           '+': '0101011', ',': '0101100', '-': '0101101', '.': '0101110', '/': '0101111', '0': '0110000', '1': '0110001', '2': '0110010',
           '3': '0110011', '4': '0110100', '5': '0110101', '6': '0110110', '7': '0110111', '8': '0111000', '9': '0111001', ':': '0111010',
           ';': '0111011', '<': '0111100', '=': '0111101', '>': '0111110', '?': '0111111', '@': '1000000', 'A': '1000001', 'B': '1000010',
           'C': '1000011', 'D': '1000100', 'E': '1000101', 'F': '1000110', 'G': '1000111', 'H': '1001000', 'I': '1001001', 'J': '1001010',
           'K': '1001011', 'L': '1001100', 'M': '1001101', 'N': '1001110', 'O': '1001111', 'P': '1010000', 'Q': '1010001', 'R': '1010010',
           'S': '1010011', 'T': '1010100', 'U': '1010101', 'V': '1010110', 'W': '1010111', 'X': '1011000', 'Y': '1011001', 'Z': '1011010',
           '[': '1011011', '\\': '1011100', ']': '1011101', '^': '1011110', '_': '1011111', '`': '1100000', 'a': '1100001', 'b': '1100010',
           'c': '1100011', 'd': '1100100', 'e': '1100101', 'f': '1100110', 'g': '1100111', 'h': '1101000', 'i': '1101001', 'j': '1101010',
           'k': '1101011', 'l': '1101100', 'm': '1101101', 'n': '1101110', 'o': '1101111', 'p': '1110000', 'q': '1110001', 'r': '1110010',
           's': '1110011', 't': '1110100', 'u': '1110101', 'v': '1110110', 'w': '1110111', 'x': '1111000', 'y': '1111001', 'z': '1111010',
           '{': '1111011', '|': '1111100', '}': '1111101', '~': '1111110', '\x7f': '1111111'}


# Constants
phi = 0x9e3779b9
r = 16
counter = 1

IPTable = [
    0, 32, 64, 96, 1, 33, 65, 97, 2, 34, 66, 98, 3, 35, 67, 99,
    4, 36, 68, 100, 5, 37, 69, 101, 6, 38, 70, 102, 7, 39, 71, 103,
    8, 40, 72, 104, 9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
    12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
    16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
    20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
    24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
    28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127,
]

FPTable = [
    0, 4, 8, 12, 16, 20, 24, 28, 32, 36, 40, 44, 48, 52, 56, 60,
    64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61,
    65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
    2, 6, 10, 14, 18, 22, 26, 30, 34, 38, 42, 46, 50, 54, 58, 62,
    66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
    3, 7, 11, 15, 19, 23, 27, 31, 35, 39, 43, 47, 51, 55, 59, 63,
    67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127,
]

# Note: In the final version of Serpent only 8 S-boxes
# are used, with each one being reused 4 times.
# SBoxDecimalTable = [
#     [ 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 ], # S0
#     [15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 ], # S1
#     [ 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 ], # S2
#     [ 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 ], # S3
#     [ 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 ], # S4
#     [15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 ], # S5
#     [ 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 ], # S6
#     [ 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 ], # S7
# ]


def convertASCII2Bin(asciiString):
    binString = ""
    for i in asciiString:
        binString += (asc2bin[i])
    return(binString)


def convertBin2ASCII(binaryString):
    asciiString = ""
    for i in range(0, len(binaryString), 7):
        asciiString += str(bin2asc[binaryString[i: i + 7]])
    return(asciiString)


S = [[[0 for _ in range(16)] for _ in range(8)] for _ in range(8)]

ss = "3 5 6 7 10 12 14 19 20 24 27 28 33 37 38 39 40 41 43 45 47 48 51 53 54 55 56 63 65 66 69 71 74 75 76 77 78 80 82 83 85 86 87 90 91 93 94 96 97 101 102 103 105 106 107 108 125 109 110 112 115 119 126 127 130 131 132 138 142 145 147 148 149 150 151 152 154 155 156 160 161 163 164 166 167 170 171 172 174 175 177 179 180 181 182 183 186 188 191 192 194 201 202 203 204 206 209 210 212 214 216 217 218 219 220 224 229 230 233 237 238 243 245 247 250 251 252 254"
gen = list(map(int, ss.split(" ")))

dp = [-1 for _ in range(8)]
dp[0] = 13

dp[0] = ((dp[0] + counter) % 128 + pow(dp[0] + counter, 2) %
         128 + pow(dp[0] + counter, 3) % 128) % 128


def function(n):
    if (n == 0):
        return 13

    if (dp[n] != -1):
        return dp[n]

    lbd = 3.9955
    dp[n] = int((lbd * function(n - 1) * (1 - function(n - 1))) % 128 + 1)
    return dp[n]


function(7)

# print(dp)

g = [gen[dp[i] - 1] for i in range(8)]

for j in range(8):
    S[j] = [pow(g[j], i + 1) % 257 for i in range(256)]

SS = []

for j in range(8):
    SS.append([S[j][16 * i:16 * (i + 1)] for i in range(16)])

# print(SS[0])
# print()
# print(SS[1])
# print()
# print(SS[2])

SBox = []

# for i in range(16):
#     print(SS[i])
#     sum = 0
#     for j in range(16):
#         sum += SS[i][j]
#         sum %= 16
#     SSS.append(sum)

# for i in range(16):
#     print(SSS[i])

for rnd in range(8):
    l = []
    for i in range(16):
        sum = 0
        for j in range(16):
            sum += SS[rnd][i][j]
            sum %= 16
        l.append(sum)
    l = list(set(l))

    for num in range(16):

        if len(l) == 16:
            break
        if num not in l:
            l.append(num)

    SBox.append(l)

# for i in range(8):
    # print(SBox[i])


SBoxDecimalTable = SBox.copy()


# The Linear Transformation Matrix
LTTable = [
    [16, 52, 56, 70, 83, 94, 105], [72, 114, 125], [2, 9, 15, 30, 76, 84, 126], [
        36, 90, 103], [20, 56, 60, 74, 87, 98, 109], [1, 76, 118],
    [2, 6, 13, 19, 34, 80, 88], [40, 94, 107], [24, 60, 64, 78, 91, 102, 113], [
        5, 80, 122], [6, 10, 17, 23, 38, 84, 92], [44, 98, 111], [28, 64, 68, 82, 95, 106, 117],
    [9, 84, 126], [10, 14, 21, 27, 42, 88, 96], [48, 102, 115], [
        32, 68, 72, 86, 99, 110, 121], [2, 13, 88], [14, 18, 25, 31, 46, 92, 100],
    [52, 106, 119], [36, 72, 76, 90, 103, 114, 125], [6, 17, 92], [
        18, 22, 29, 35, 50, 96, 104], [56, 110, 123], [1, 40, 76, 80, 94, 107, 118],
    [10, 21, 96], [22, 26, 33, 39, 54, 100, 108], [60, 114, 127], [
        5, 44, 80, 84, 98, 111, 122], [14, 25, 100], [26, 30, 37, 43, 58, 104, 112],
    [3, 118], [9, 48, 84, 88, 102, 115, 126], [18, 29, 104], [
        30, 34, 41, 47, 62, 108, 116], [7, 122], [2, 13, 52, 88, 92, 106, 119],
    [22, 33, 108], [34, 38, 45, 51, 66, 112, 120], [11, 126], [6, 17, 56,
                                                               92, 96, 110, 123], [26, 37, 112], [38, 42, 49, 55, 70, 116, 124],
    [2, 15, 76], [10, 21, 60, 96, 100, 114, 127], [30, 41, 116], [
        0, 42, 46, 53, 59, 74, 120], [6, 19, 80], [3, 14, 25, 100, 104, 118],
    [34, 45, 120], [4, 46, 50, 57, 63, 78, 124], [10, 23, 84], [
        7, 18, 29, 104, 108, 122], [38, 49, 124], [0, 8, 50, 54, 61, 67, 82],
    [14, 27, 88], [11, 22, 33, 108, 112, 126], [0, 42, 53], [4, 12, 54, 58,
                                                             65, 71, 86], [18, 31, 92], [2, 15, 26, 37, 76, 112, 116], [4, 46, 57],
    [8, 16, 58, 62, 69, 75, 90], [22, 35, 96], [6, 19, 30, 41, 80, 116, 120], [
        8, 50, 61], [12, 20, 62, 66, 73, 79, 94], [26, 39, 100],
    [10, 23, 34, 45, 84, 120, 124], [12, 54, 65], [16, 24, 66, 70, 77, 83, 98], [
        30, 43, 104], [0, 14, 27, 38, 49, 88, 124], [16, 58, 69],
    [20, 28, 70, 74, 81, 87, 102], [34, 47, 108], [0, 4, 18, 31, 42, 53, 92], [
        20, 62, 73], [24, 32, 74, 78, 85, 91, 106], [38, 51, 112],
    [4, 8, 22, 35, 46, 57, 96], [24, 66, 77], [28, 36, 78, 82, 89, 95, 110], [
        42, 55, 116], [8, 12, 26, 39, 50, 61, 100], [28, 70, 81],
    [32, 40, 82, 86, 93, 99, 114], [46, 59, 120], [12, 16, 30, 43, 54, 65, 104], [
        32, 74, 85], [36, 90, 103, 118], [50, 63, 124], [16, 20, 34, 47, 58, 69, 108],
    [36, 78, 89], [40, 94, 107, 122], [0, 54, 67], [20, 24, 38, 51, 62, 73, 112], [
        40, 82, 93], [44, 98, 111, 126], [4, 58, 71], [24, 28, 42, 55, 66, 77, 116],
    [44, 86, 97], [2, 48, 102, 115], [8, 62, 75], [28, 32, 46, 59, 70, 81, 120], [
        48, 90, 101], [6, 52, 106, 119], [12, 66, 79], [32, 36, 50, 63, 74, 85, 124],
    [52, 94, 105], [10, 56, 110, 123], [16, 70, 83], [0, 36, 40, 54,
                                                      67, 78, 89], [56, 98, 109], [14, 60, 114, 127], [20, 74, 87],
    [4, 40, 44, 58, 71, 82, 93], [60, 102, 113], [3, 18, 72, 114, 118, 125], [
        24, 78, 91], [8, 44, 48, 62, 75, 86, 97], [64, 106, 117],
    [1, 7, 22, 76, 118, 122], [28, 82, 95], [12, 48, 52, 66, 79, 90, 101], [
        68, 110, 121], [5, 11, 26, 80, 122, 126], [32, 86, 99],
]

# The following table is necessary for the decryption.
LTTableInverse = [
    [53, 55, 72], [1, 5, 20, 90], [15, 102], [3, 31, 90], [57, 59, 76], [
        5, 9, 24, 94], [19, 106], [7, 35, 94], [61, 63, 80], [9, 13, 28, 98],
    [23, 110], [11, 39, 98], [65, 67, 84], [13, 17, 32, 102], [27, 114], [
        1, 3, 15, 20, 43, 102], [69, 71, 88], [17, 21, 36, 106], [1, 31, 118],
    [5, 7, 19, 24, 47, 106], [73, 75, 92], [21, 25, 40, 110], [5, 35, 122], [
        9, 11, 23, 28, 51, 110], [77, 79, 96], [25, 29, 44, 114], [9, 39, 126],
    [13, 15, 27, 32, 55, 114], [81, 83, 100], [1, 29, 33, 48, 118], [2, 13, 43], [
        1, 17, 19, 31, 36, 59, 118], [85, 87, 104], [5, 33, 37, 52, 122],
    [6, 17, 47], [5, 21, 23, 35, 40, 63, 122], [89, 91, 108], [9, 37, 41,
                                                               56, 126], [10, 21, 51], [9, 25, 27, 39, 44, 67, 126], [93, 95, 112],
    [2, 13, 41, 45, 60], [14, 25, 55], [2, 13, 29, 31, 43, 48, 71], [
        97, 99, 116], [6, 17, 45, 49, 64], [18, 29, 59], [6, 17, 33, 35, 47, 52, 75],
    [101, 103, 120], [10, 21, 49, 53, 68], [22, 33, 63], [10, 21, 37, 39,
                                                          51, 56, 79], [105, 107, 124], [14, 25, 53, 57, 72], [26, 37, 67],
    [14, 25, 41, 43, 55, 60, 83], [0, 109, 111], [18, 29, 57, 61, 76], [
        30, 41, 71], [18, 29, 45, 47, 59, 64, 87], [4, 113, 115], [22, 33, 61, 65, 80],
    [34, 45, 75], [22, 33, 49, 51, 63, 68, 91], [8, 117, 119], [26, 37, 65,
                                                                69, 84], [38, 49, 79], [26, 37, 53, 55, 67, 72, 95], [12, 121, 123],
    [30, 41, 69, 73, 88], [42, 53, 83], [30, 41, 57, 59, 71, 76, 99], [16, 125,
                                                                       127], [34, 45, 73, 77, 92], [46, 57, 87], [34, 45, 61, 63, 75, 80, 103],
    [1, 3, 20], [38, 49, 77, 81, 96], [50, 61, 91], [38, 49, 65, 67, 79, 84, 107], [
        5, 7, 24], [42, 53, 81, 85, 100], [54, 65, 95], [42, 53, 69, 71, 83, 88, 111],
    [9, 11, 28], [46, 57, 85, 89, 104], [58, 69, 99], [46, 57, 73, 75, 87, 92, 115], [
        13, 15, 32], [50, 61, 89, 93, 108], [62, 73, 103], [50, 61, 77, 79, 91, 96, 119],
    [17, 19, 36], [54, 65, 93, 97, 112], [66, 77, 107], [54, 65, 81, 83,
                                                         95, 100, 123], [21, 23, 40], [58, 69, 97, 101, 116], [70, 81, 111],
    [58, 69, 85, 87, 99, 104, 127], [25, 27, 44], [62, 73, 101, 105, 120], [
        74, 85, 115], [3, 62, 73, 89, 91, 103, 108], [29, 31, 48], [66, 77, 105, 109, 124],
    [78, 89, 119], [7, 66, 77, 93, 95, 107, 112], [33, 35, 52], [0, 70, 81,
                                                                 109, 113], [82, 93, 123], [11, 70, 81, 97, 99, 111, 116], [37, 39, 56],
    [4, 74, 85, 113, 117], [86, 97, 127], [15, 74, 85, 101, 103, 115, 120], [
        41, 43, 60], [8, 78, 89, 117, 121], [3, 90], [19, 78, 89, 105, 107, 119, 124],
    [45, 47, 64], [12, 82, 93, 121, 125], [7, 94], [0, 23, 82, 93, 109, 111, 123], [
        49, 51, 68], [1, 16, 86, 97, 125], [11, 98], [4, 27, 86, 97, 113, 115, 127],
]


def IP(input):
    """Apply the Initial Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""
    return applyPermutation(IPTable, input)


def FP(input):
    """Apply the Final Permutation to the 128-bit bitstring 'input'
    and return a 128-bit bitstring as the result."""
    return applyPermutation(FPTable, input)


def IPInverse(output):
    """Apply the Initial Permutation in reverse."""
    return FP(output)


def FPInverse(output):
    """Apply the Final Permutation in reverse."""
    return IP(output)


def applyPermutation(permutationTable, input):
    """Apply the permutation specified by the 128-element list
    'permutationTable' to the 128-bit bitstring 'input' and return a
    128-bit bitstring as the result."""
    result = ""
    for i in range(len(permutationTable)):
        result = result + input[permutationTable[i]]
    return result


# --------------------------------------------------------------
# Hex conversion functions
bin2hex = {
    # Given a 4-char bitstring, return the corresponding 1-char hex-string
    "0000": "0", "1000": "1", "0100": "2", "1100": "3",
    "0010": "4", "1010": "5", "0110": "6", "1110": "7",
    "0001": "8", "1001": "9", "0101": "a", "1101": "b",
    "0011": "c", "1011": "d", "0111": "e", "1111": "f",
}

# Make the reverse lookup table too
hex2bin = {}
for (bin, hex) in bin2hex.items():
    hex2bin[hex] = bin


def bitstring(n, minlen=1):
    """Translate n from integer to bitstring, padding it with 0s as
    necessary to reach the minimum length 'minlen'. 'n' must be >= 0 since
    the bitstring format is undefined for negative integers.
    EXAMPLE: bitstring(10, 8) -> "01010000"
    """
    result = ""
    while n > 0:
        if n & 1:
            result = result + "1"
        else:
            result = result + "0"
        n = n >> 1
    if len(result) < minlen:
        result = result + "0" * (minlen - len(result))
    return result


def bitstring2hexstring(b):
    """Take bitstring 'b' and return the corresponding hexstring."""
    result = ""
    l = len(b)
    if l % 4:
        b = b + "0" * (4-(l % 4))
    for i in range(0, len(b), 4):
        result = result+bin2hex[b[i:i+4]]
    return reverseString(result)


def hexstring2bitstring(h):
    """Take hexstring 'h' and return the corresponding bitstring."""
    result = ""
    for c in reverseString(h):
        result = result + hex2bin[c]
    return result


def reverseString(s):
    l = list(s)
    l.reverse()
    return string.join(l, "")


# Make another version of this table as a list of dictionaries: one dictionary per S-box, where the value of the entry indexed by i tells you
# the output configuration when the input is i, with both the index and the value being bit-strings.  Make also the inverse: another list of
# dictionaries, one per S-box, where each dictionary gets the output of the S-box as the key and gives you the input, with both values being 4-bit
# bit-strings.
SBoxBitstring = []
SBoxBitstringInverse = []
for line in SBoxDecimalTable:
    dict = {}
    inverseDict = {}
    for i in range(len(line)):
        index = bitstring(i, 4)
        value = bitstring(line[i], 4)
        dict[index] = value
        inverseDict[value] = index
    SBoxBitstring.append(dict)
    SBoxBitstringInverse.append(inverseDict)


def S(box, input):
    """Apply S-box number 'box' to 4-bit bitstring 'input' and return a
    4-bit bitstring as the result."""
    return SBoxBitstring[box % 8][input]


def SInverse(box, output):
    """Apply S-box number 'box' in reverse to 4-bit bitstring 'output' and
    return a 4-bit bitstring (the input) as the result."""
    return SBoxBitstringInverse[box % 8][output]


def SHat(box, input):
    """Apply a parallel array of 32 copies of S-box number 'box' to the
    128-bit bitstring 'input' and return a 128-bit bitstring as the
    result."""
    result = ""
    for i in range(32):
        result = result + S(box, input[4*i:4*(i+1)])
    return result


def SHatInverse(box, output):
    """Apply, in reverse, a parallel array of 32 copies of S-box number
    'box' to the 128-bit bitstring 'output' and return a 128-bit bitstring
    (the input) as the result."""
    result = ""
    for i in range(32):
        result = result + SInverse(box, output[4*i:4*(i+1)])
    return result


def SBitslice(box, words):
    """Take 'words', a list of 4 32-bit bitstrings, least significant word
    first. Return a similar list of 4 32-bit bitstrings obtained as
    follows. For each bit position from 0 to 31, apply S-box number 'box'
    to the 4 input bits coming from the current position in each of the
    items in 'words'; and put the 4 output bits in the corresponding
    positions in the output words."""
    result = ["", "", "", ""]
    for i in range(32):  # ideally in parallel
        quad = S(box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result


def SBitsliceInverse(box, words):
    """Take 'words', a list of 4 32-bit bitstrings, least significant word
    first. Return a similar list of 4 32-bit bitstrings obtained as
    follows. For each bit position from 0 to 31, apply S-box number 'box'
    in reverse to the 4 output bits coming from the current position in
    each of the items in the supplied 'words'; and put the 4 input bits in
    the corresponding positions in the returned words."""
    result = ["", "", "", ""]
    for i in range(32):  # ideally in parallel
        quad = SInverse(
            box, words[0][i] + words[1][i] + words[2][i] + words[3][i])
        for j in range(4):
            result[j] = result[j] + quad[j]
    return result


def LT(input):
    """Apply the table-based version of the linear transformation to the
    128-bit string 'input' and return a 128-bit string as the result."""
    result = ""
    for i in range(len(LTTable)):
        outputBit = "0"
        for j in LTTable[i]:
            outputBit = xor(outputBit, input[j])
        result = result + outputBit
    return result


def LTInverse(output):
    """Apply the table-based version of the inverse of the linear
    transformation to the 128-bit string 'output' and return a 128-bit
    string (the input) as the result."""

    result = ""
    for i in range(len(LTTableInverse)):
        inputBit = "0"
        for j in LTTableInverse[i]:
            inputBit = xor(inputBit, output[j])
        result = result + inputBit
    return result


def LTBitslice(X):
    """Apply the equations-based version of the linear transformation to
    'X', a list of 4 32-bit bitstrings, least significant bitstring first,
    and return another list of 4 32-bit bitstrings as the result."""
    X[0] = rotateLeft(X[0], 13)
    X[2] = rotateLeft(X[2], 3)
    X[1] = xor(X[1], X[0], X[2])
    X[3] = xor(X[3], X[2], shiftLeft(X[0], 3))
    X[1] = rotateLeft(X[1], 1)
    X[3] = rotateLeft(X[3], 7)
    X[0] = xor(X[0], X[1], X[3])
    X[2] = xor(X[2], X[3], shiftLeft(X[1], 7))
    X[0] = rotateLeft(X[0], 5)
    X[2] = rotateLeft(X[2], 22)

    return X


def LTBitsliceInverse(X):
    """Apply, in reverse, the equations-based version of the linear
    transformation to 'X', a list of 4 32-bit bitstrings, least significant
    bitstring first, and return another list of 4 32-bit bitstrings as the
    result."""
    X[2] = rotateRight(X[2], 22)
    X[0] = rotateRight(X[0], 5)
    X[2] = xor(X[2], X[3], shiftLeft(X[1], 7))
    X[0] = xor(X[0], X[1], X[3])
    X[3] = rotateRight(X[3], 7)
    X[1] = rotateRight(X[1], 1)
    X[3] = xor(X[3], X[2], shiftLeft(X[0], 3))
    X[1] = xor(X[1], X[0], X[2])
    X[2] = rotateRight(X[2], 3)
    X[0] = rotateRight(X[0], 13)
    return X


def binaryXor(n1, n2):
    """
    EXAMPLE: binaryXor("10010", "00011") -> "10001"
    """
    result = ""
    for i in range(len(n1)):
        if n1[i] == n2[i]:
            result = result + "0"
        else:
            result = result + "1"
    return result


def xor(*args):
    """
    EXAMPLE: xor("01", "11", "10") -> "00"
    """
    result = args[0]
    for arg in args[1:]:
        result = binaryXor(result, arg)
    return result


def rotateLeft(input, places):
    """
    EXAMPLE: rotateLeft("000111", 2) -> "110001"
    """
    p = places % len(input)
    return input[-p:] + input[:-p]


def rotateRight(input, places):
    return rotateLeft(input, -places)


def shiftLeft(input, p):
    """
    EXAMPLE: shiftLeft("000111", 2) -> "000001"
             shiftLeft("000111", -2) -> "011100"
    """

    if abs(p) >= len(input):
        # Everything gets shifted out anyway
        return "0" * len(input)
    if p < 0:
        # Shift right instead
        return input[-p:] + "0" * len(input[:-p])
    elif p == 0:
        return input
    else:  # p > 0, normal case
        return "0" * len(input[-p:]) + input[:-p]


def shiftRight(input, p):
    """Take a bitstring 'input' and shift it right by 'p' places. See the
    doc for shiftLeft for more details."""
    return shiftLeft(input, -p)


def keyLengthInBitsOf(k):
    """Take a string k in I/O format and return the number of bits in it."""
    return len(k) * 4


def R(i, BHati, KHat):
    """Apply round 'i' to the 128-bit bitstring 'BHati', returning another
    128-bit bitstring (conceptually BHatiPlus1). Do this using the
    appropriately numbered subkey(s) from the 'KHat' list of 33 128-bit
    bitstrings."""
    xored = xor(BHati, KHat[i])
    SHati = SHat(i, xored)

    if 0 <= i <= r-2:
        BHatiPlus1 = LT(SHati)
    elif i == r-1:
        BHatiPlus1 = xor(SHati, KHat[r])

    return BHatiPlus1


def RInverse(i, BHatiPlus1, KHat):
    """Apply round 'i' in reverse to the 128-bit bitstring 'BHatiPlus1',
    returning another 128-bit bitstring (conceptually BHati). Do this using
    the appropriately numbered subkey(s) from the 'KHat' list of 33 128-bit
    bitstrings."""
    if 0 <= i <= r-2:
        SHati = LTInverse(BHatiPlus1)
    elif i == r-1:
        SHati = xor(BHatiPlus1, KHat[r])
    xored = SHatInverse(i, SHati)

    BHati = xor(xored, KHat[i])

    return BHati


def quadSplit(b128):
    """Take a 128-bit bitstring and return it as a list of 4 32-bit
    bitstrings, least significant bitstring first."""

    result = []
    for i in range(4):
        result.append(b128[(i*32):(i+1)*32])
    return result


def quadJoin(l4x32):
    """Take a list of 4 32-bit bitstrings and return it as a single 128-bit
    bitstring obtained by concatenating the internal ones."""

    return l4x32[0] + l4x32[1] + l4x32[2] + l4x32[3]


def RBitslice(i, Bi, K):
    """Apply round 'i' (bitslice version) to the 128-bit bitstring 'Bi' and
    return another 128-bit bitstring (conceptually B i+1). Use the
    appropriately numbered subkey(s) from the 'K' list of 33 128-bit
    bitstrings."""
    # 1. Key mixing
    xored = xor(Bi, K[i])

    # 2. S Boxes
    Si = SBitslice(i, quadSplit(xored))
    # Input and output to SBitslice are both lists of 4 32-bit bitstrings

    # 3. Linear Transformation
    if i == r-1:
        # In the last round, replaced by an additional key mixing
        BiPlus1 = xor(quadJoin(Si), K[r])
    else:
        BiPlus1 = quadJoin(LTBitslice(Si))
    # BIPlus1 is a 128-bit bitstring

    return BiPlus1


def RBitsliceInverse(i, BiPlus1, K):
    """Apply the inverse of round 'i' (bitslice version) to the 128-bit
    bitstring 'BiPlus1' and return another 128-bit bitstring (conceptually
    B i). Use the appropriately numbered subkey(s) from the 'K' list of 33
    128-bit bitstrings."""
    # 3. Linear Transformation
    if i == r-1:
        # In the last round, replaced by an additional key mixing
        Si = quadSplit(xor(BiPlus1, K[r]))
    else:
        Si = LTBitsliceInverse(quadSplit(BiPlus1))
    # SOutput (same as LTInput) is a list of 4 32-bit bitstrings
    # 2. S Boxes
    xored = SBitsliceInverse(i, Si)
    # SInput and SOutput are both lists of 4 32-bit bitstrings

    # 1. Key mixing
    Bi = xor(quadJoin(xored), K[i])

    return Bi


def encrypt(plainText, userKey):
    """Encrypt the 128-bit bitstring 'plainText' with the 256-bit bitstring
    'userKey', using the normal algorithm, and return a 128-bit ciphertext
    bitstring."""
    K, KHat = makeSubkeys(userKey)

    BHat = IP(plainText)  # BHat_0 at this stage
    for i in range(r):
        BHat = R(i, BHat, KHat)  # Produce BHat_i+1 from BHat_i
    # BHat is now _32 i.e. _r
    C = FP(BHat)

    return C


def encryptBitslice(plainText, userKey):
    """Encrypt the 128-bit bitstring 'plainText' with the 256-bit bitstring
    'userKey', using the bitslice algorithm, and return a 128-bit ciphertext
    bitstring."""
    K, KHat = makeSubkeys(userKey)

    B = plainText  # B_0 at this stage
    for i in range(r):
        B = RBitslice(i, B, K)  # Produce B_i+1 from B_i
    # B is now _r

    return B


def decrypt(cipherText, userKey):
    """Decrypt the 128-bit bitstring 'cipherText' with the 256-bit
    bitstring 'userKey', using the normal algorithm, and return a 128-bit
    plaintext bitstring."""
    K, KHat = makeSubkeys(userKey)

    BHat = FPInverse(cipherText)  # BHat_r at this stage
    for i in range(r-1, -1, -1):  # from r-1 down to 0 included
        BHat = RInverse(i, BHat, KHat)  # Produce BHat_i from BHat_i+1
    # BHat is now _0
    plainText = IPInverse(BHat)

    return plainText


def decryptBitslice(cipherText, userKey):
    """Decrypt the 128-bit bitstring 'cipherText' with the 256-bit
    bitstring 'userKey', using the bitslice algorithm, and return a 128-bit
    plaintext bitstring."""
    K, KHat = makeSubkeys(userKey)

    B = cipherText  # B_r at this stage
    for i in range(r-1, -1, -1):  # from r-1 down to 0 included
        B = RBitsliceInverse(i, B, K)  # Produce B_i from B_i+1
    # B is now _0

    return B


def makeSubkeys(userKey):
    """Given the 256-bit bitstring 'userKey' (shown as K in the paper, but
    we can't use that name because of a collision with K[i] used later for
    something else), return two lists (conceptually K and KHat) of 33
    128-bit bitstrings each."""
    w = {}
    for i in range(-8, 0):
        w[i] = userKey[(i+8)*32:(i+9)*32]

    # We expand these to a prekey w0 ... w131 with the affine recurrence
    for i in range(132):
        w[i] = rotateLeft(
            xor(w[i-8], w[i-5], w[i-3], w[i-1],
                bitstring(phi, 32), bitstring(i, 32)),
            11)

    # The round keys are now calculated from the prekeys using the S-boxes
    # in bitslice mode. Each k[i] is a 32-bit bitstring.
    k = {}
    for i in range(r+1):
        whichS = (r + 3 - i) % r
        k[0+4*i] = ""
        k[1+4*i] = ""
        k[2+4*i] = ""
        k[3+4*i] = ""
        for j in range(32):  # for every bit in the k and w words
            # ENOTE: w0 and k0 are the least significant words, w99 and k99
            # the most.
            input = w[0+4*i][j] + w[1+4*i][j] + w[2+4*i][j] + w[3+4*i][j]
            output = S(whichS, input)
            for l in range(4):
                k[l+4*i] = k[l+4*i] + output[l]

    # We then renumber the 32 bit values k_j as 128 bit subkeys K_i.
    K = []
    for i in range(r+1):
        # ENOTE: k4i is the least significant word, k4i+3 the most.
        K.append(k[4*i] + k[4*i+1] + k[4*i+2] + k[4*i+3])

    # We now apply IP to the round key in order to place the key bits in
    # the correct column
    KHat = []
    for i in range(r+1):
        KHat.append(IP(K[i]))

    return K, KHat


def makeLongKey(k):
    """Take a key k in bitstring format. Return the long version of that
    key."""
    l = len(k)
    if l == 256:
        return k
    else:
        return k + "1" + "0"*(256 - l - 1)


def driver_function(plain_text, key):

    print("Entered plain text is: " + plain_text)
    cipher = encrypt(plain_text, key)
    print()
    print("Encrypted message is:  " + cipher)
    decoded_msg = decrypt(cipher, key)
    print("Decoded message is:    " + decoded_msg)
    print()

    # Checking if the actual message is equal to decoded message
    if(decoded_msg == plain_text):
        print("Successfull Encryption and Decryption...")
    else:
        print("Un-Successfull Encryption and Decryption...")


if __name__ == "__main__":

   #  plain_text = "11011110"*16  # 128 bits plain text
    key = "10010101"*32  # 256 bits secret key
   #  driver_function(plain_text, key)
    print('Starting to send')
    with open("AA.jpg", "rb") as image_file:
        encoded_string = base64.b64encode(image_file.read())
      #   print((encoded_string))

        s = encoded_string.decode('utf-8')

        b = convertASCII2Bin(s)

      #   print(b)
        # print()
        # print(s)
        # # # print(binascii.a2b_base64(encoded_string))
        # print()
        # print(s.encode('ascii'))
        # decoded = base64.decodebytes(encoded_string)
        # # print(decoded)
        # b = ("".join(["{:08b}".format(x) for x in decoded]))
        # print(b)
        ll = len(b)

        b = b + "0"*(128-len(b) % 128)
      #   print(len(b)//128)
        idx = 0
        cipher = ""
        # c = 1
        lll = len(b)
      #   print(len(b))
        c = len(b)//128
        while(c):
            cipher += encrypt(b[idx*128:idx*128+128], key)
            print(c)
            idx += 1
            c -= 1

        # while(idx*128 < len(b)):
        #     print(c)
        #     c += 1
        #     # print("711: ",len(b[idx*128:idx+128]))
        #     cipher += encrypt(b[idx*128:idx+128], key)
        #     idx *= 128
        print('Encryption done')
        # print("715: ",cipher)
        print("cipher: ", len(cipher))

        # cipher = cipher[:ll]
        # cipher += "0"*(128-len(b)%128)

   #      idx = 0
   #      dec = ""
   #      # c = 1
   #    #   print(len(cipher))
   #      c = len(b)//128
   #      while(c):
   #          dec += decrypt(cipher[idx*128:idx*128+128], key)
   #          # print(c)
   #          idx += 1
   #          c -= 1

   #    #   print(b[128:128*2])
   #    #   print(dec[128:128*2])
   #    #   print(b[:128*2] == dec[:128*2])
   #    #   print('b: ', len(b))
   #      if(b[:ll] == dec[:ll]):
   #          print("yo")
   #      else:
   #          print("No")

   #  # val = '0b' + dec
   #  # val = 3>> bin(int('01010101', 2))
   #  # img_data =  struct.pack('I', val).encode('base64')

   #  img = convertBin2ASCII(dec[:ll]).encode('ascii')
   # #  print(img)
   #  print(img.decode('ascii') == s)
   #  with open("imageToSave.png", "wb") as fh:
   #      fh.write(base64.decodebytes(img))
   #  print(ll)
    s = socket.socket()  # Create a socket object
    port = 11111
    s.bind(("", port))  # Next bind to the port, Empty quotes -> any ip address
    s.listen(5)  # 5 -> Maximum number of backlog connections

    while(True):
        # Establish connection with client.
        c, addr = s.accept()
        print("Got connection from", addr)
        msg = (str(ll) + ":" + str(lll) + ":" + cipher).encode("utf-8")
        c.send(msg)
        print('Message sent')
        c.close()
