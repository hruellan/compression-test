# Copyright (c) 2012 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

request_freq_table = [
  (   0,      0),(   1,      0),(   2,      0),
  (   3,      0),(   4,      0),(   5,      0),
  (   6,      0),(   7,      0),(   8,      0),
  (   9,      0),(  10,      0),(  11,      0),
  (  12,      0),(  13,      0),(  14,      0),
  (  15,      0),(  16,      0),(  17,      0),
  (  18,      0),(  19,      0),(  20,      0),
  (  21,      0),(  22,      0),(  23,      0),
  (  24,      0),(  25,      0),(  26,      0),
  (  27,      0),(  28,      0),(  29,      0),
  (  30,      0),(  31,      0),( ' ',   7610),
  ( '!',    930),( '"',    202),( '#',    134),
  ( '$',    123),( '%',  44564),( '&',  25746),
  ( "'",    103),( '(',   1917),( ')',   1958),
  ( '*',   3102),( '+',   1031),( ',',   7830),
  ( '-',  38776),( '.',  61420),( '/', 115378),
  ( '0',  78519),( '1',  75265),( '2',  83362),
  ( '3',  54510),( '4',  37403),( '5',  40823),
  ( '6',  35068),( '7',  36398),( '8',  33595),
  ( '9',  36340),( ':',   5530),( ';',   9240),
  ( '<',     16),( '=',  42481),( '>',     50),
  ( '?',   5865),( '@',    205),( 'A',  16369),
  ( 'B',   9310),( 'C',  11301),( 'D',  12701),
  ( 'E',   7543),( 'F',  17618),( 'G',   5510),
  ( 'H',   5226),( 'I',   6981),( 'J',   4233),
  ( 'K',   3072),( 'L',   5795),( 'M',   8677),
  ( 'N',   5276),( 'O',   6132),( 'P',   5241),
  ( 'Q',   4150),( 'R',   5655),( 'S',   8546),
  ( 'T',   8826),( 'U',   5201),( 'V',   5305),
  ( 'W',   6627),( 'X',   5961),( 'Y',   4464),
  ( 'Z',   3212),( '[',    266),('\\',      0),
  ( ']',    275),( '^',    149),( '_',  34919),
  ( '`',      9),( 'a',  85465),( 'b',  32815),
  ( 'c',  67786),( 'd',  50950),( 'e', 125495),
  ( 'f',  33026),( 'g',  46142),( 'h',  30069),
  ( 'i',  87001),( 'j',  21311),( 'k',  14902),
  ( 'l',  55591),( 'm',  55290),( 'n',  64016),
  ( 'o',  72711),( 'p',  57459),( 'q',   8956),
  ( 'r',  60591),( 's',  84899),( 't',  90992),
  ( 'u',  35484),( 'v',  16925),( 'w',  29268),
  ( 'x',  14687),( 'y',  13536),( 'z',   7943),
  ( '{',     30),( '|',    988),( '}',     30),
  ( '~',    748),( 127,      0),( 128,      0),
  ( 129,      0),( 130,      0),( 131,      0),
  ( 132,      0),( 133,      0),( 134,      0),
  ( 135,      0),( 136,      0),( 137,      0),
  ( 138,      0),( 139,      0),( 140,      0),
  ( 141,      0),( 142,      0),( 143,      0),
  ( 144,      0),( 145,      0),( 146,      0),
  ( 147,      0),( 148,      0),( 149,      0),
  ( 150,      0),( 151,      0),( 152,      0),
  ( 153,      0),( 154,      0),( 155,      0),
  ( 156,      0),( 157,      0),( 158,      0),
  ( 159,      0),( 160,      0),( 161,      0),
  ( 162,      0),( 163,      0),( 164,      0),
  ( 165,      0),( 166,      0),( 167,      0),
  ( 168,      0),( 169,      0),( 170,      0),
  ( 171,      0),( 172,      0),( 173,      0),
  ( 174,      0),( 175,      0),( 176,      0),
  ( 177,      0),( 178,      0),( 179,      0),
  ( 180,      0),( 181,      0),( 182,      0),
  ( 183,      0),( 184,      0),( 185,      0),
  ( 186,      0),( 187,      0),( 188,      0),
  ( 189,      0),( 190,      0),( 191,      0),
  ( 192,      0),( 193,      0),( 194,      0),
  ( 195,      0),( 196,      0),( 197,      0),
  ( 198,      0),( 199,      0),( 200,      0),
  ( 201,      0),( 202,      0),( 203,      0),
  ( 204,      0),( 205,      0),( 206,      0),
  ( 207,      0),( 208,      0),( 209,      0),
  ( 210,      0),( 211,      0),( 212,      0),
  ( 213,      0),( 214,      0),( 215,      0),
  ( 216,      0),( 217,      0),( 218,      0),
  ( 219,      0),( 220,      0),( 221,      0),
  ( 222,      0),( 223,      0),( 224,      0),
  ( 225,      0),( 226,      0),( 227,      0),
  ( 228,      0),( 229,      0),( 230,      0),
  ( 231,      0),( 232,      0),( 233,      0),
  ( 234,      0),( 235,      0),( 236,      0),
  ( 237,      0),( 238,      0),( 239,      0),
  ( 240,      0),( 241,      0),( 242,      0),
  ( 243,      0),( 244,      0),( 245,      0),
  ( 246,      0),( 247,      0),( 248,      0),
  ( 249,      0),( 250,      0),( 251,      0),
  ( 252,      0),( 253,      0),( 254,      0),
  ( 255,      0),( 256,  33889),
]

response_freq_table = [
  (   0,      0),(   1,      0),(   2,      0),
  (   3,      0),(   4,      0),(   5,      0),
  (   6,      0),(   7,      0),(   8,      0),
  (   9,      0),(  10,      0),(  11,      0),
  (  12,      0),(  13,      0),(  14,      0),
  (  15,      0),(  16,      0),(  17,      0),
  (  18,      0),(  19,      0),(  20,      0),
  (  21,      0),(  22,      0),(  23,      0),
  (  24,      0),(  25,      0),(  26,      0),
  (  27,      0),(  28,      0),(  29,      0),
  (  30,      0),(  31,      0),( ' ', 172375),
  ( '!',    473),( '"',  13272),( '#',    183),
  ( '$',     61),( '%',   2657),( '&',   1589),
  ( "'",    211),( '(',   3754),( ')',   3785),
  ( '*',    370),( '+',   1191),( ',',  34525),
  ( '-',  26062),( '.',  23541),( '/',  12241),
  ( '0', 117394),( '1', 134469),( '2', 122382),
  ( '3',  71163),( '4',  58165),( '5',  51636),
  ( '6',  39978),( '7',  40887),( '8',  48498),
  ( '9',  42766),( ':',  60664),( ';',   4316),
  ( '<',     19),( '=',  13958),( '>',     96),
  ( '?',    359),( '@',     15),( 'A',  12315),
  ( 'B',   5339),( 'C',   6633),( 'D',   6866),
  ( 'E',   6922),( 'F',   9760),( 'G',  30326),
  ( 'H',   3827),( 'I',   6145),( 'J',   7748),
  ( 'K',   1863),( 'L',   3633),( 'M',  37849),
  ( 'N',   8346),( 'O',   7175),( 'P',   4494),
  ( 'Q',   2389),( 'R',   3339),( 'S',  23801),
  ( 'T',  47093),( 'U',   3671),( 'V',   2909),
  ( 'W',   7187),( 'X',   2260),( 'Y',   2436),
  ( 'Z',   1980),( '[',    724),('\\',    122),
  ( ']',    735),( '^',     53),( '_',   3823),
  ( '`',     12),( 'a',  52595),( 'b',  15736),
  ( 'c',  41143),( 'd',  24731),( 'e',  64607),
  ( 'f',  19373),( 'g',  18801),( 'h',  16429),
  ( 'i',  28479),( 'j',   4545),( 'k',   4740),
  ( 'l',  17737),( 'm',  20585),( 'n',  28096),
  ( 'o',  35949),( 'p',  27630),( 'q',   4091),
  ( 'r',  26111),( 's',  21098),( 't',  29704),
  ( 'u',  26652),( 'v',  10503),( 'w',   5251),
  ( 'x',  11828),( 'y',   6472),( 'z',   3535),
  ( '{',     16),( '|',     79),( '}',     16),
  ( '~',     24),( 127,      0),( 128,      0),
  ( 129,      0),( 130,      0),( 131,      0),
  ( 132,      0),( 133,      0),( 134,      0),
  ( 135,      0),( 136,      0),( 137,      0),
  ( 138,      0),( 139,      0),( 140,      0),
  ( 141,      0),( 142,      0),( 143,      0),
  ( 144,      0),( 145,      0),( 146,      0),
  ( 147,      0),( 148,      0),( 149,      0),
  ( 150,      0),( 151,      0),( 152,      0),
  ( 153,      0),( 154,      0),( 155,      0),
  ( 156,      0),( 157,      0),( 158,      0),
  ( 159,      0),( 160,      0),( 161,      0),
  ( 162,      0),( 163,      0),( 164,      0),
  ( 165,      0),( 166,      0),( 167,      0),
  ( 168,      0),( 169,      0),( 170,      0),
  ( 171,      0),( 172,      0),( 173,      0),
  ( 174,      0),( 175,      0),( 176,      0),
  ( 177,      0),( 178,      0),( 179,      0),
  ( 180,      0),( 181,      0),( 182,      0),
  ( 183,      0),( 184,      0),( 185,      0),
  ( 186,      0),( 187,      0),( 188,      0),
  ( 189,      0),( 190,      0),( 191,      0),
  ( 192,      0),( 193,      0),( 194,      0),
  ( 195,      0),( 196,      0),( 197,      0),
  ( 198,      0),( 199,      0),( 200,      0),
  ( 201,      0),( 202,      0),( 203,      0),
  ( 204,      0),( 205,      0),( 206,      0),
  ( 207,      0),( 208,      0),( 209,      0),
  ( 210,      0),( 211,      0),( 212,      0),
  ( 213,      0),( 214,      0),( 215,      0),
  ( 216,      0),( 217,      0),( 218,      0),
  ( 219,      0),( 220,      0),( 221,      0),
  ( 222,      0),( 223,      0),( 224,      0),
  ( 225,      0),( 226,      0),( 227,      0),
  ( 228,      0),( 229,      0),( 230,      0),
  ( 231,      0),( 232,      0),( 233,      0),
  ( 234,      0),( 235,      0),( 236,      0),
  ( 237,      0),( 238,      0),( 239,      0),
  ( 240,      0),( 241,      0),( 242,      0),
  ( 243,      0),( 244,      0),( 245,      0),
  ( 246,      0),( 247,      0),( 248,      0),
  ( 249,      0),( 250,      0),( 251,      0),
  ( 252,      0),( 253,      0),( 254,      0),
  ( 255,      0),( 256,  84578),
]

