## Variants

|    | bit order |
|----|-----------|
| 1a | get_trivial_responder |
| 1b | get_rev_responder -- reverse bits on the wire |
| 1c | get_bitswapped_responder |
| 1d | get_rev_bitswapped_responder |
| 1e | get_wordbitswapped_responder |
| 1f | get_rev_wordbitswapped_responder |
| 1g | get_longbitswapped_responder |
| 1h | get_rev_longbitswapped_responder |

|    | argument order |
|----|----------------|
| 2a | get_trivial_responder |
| 2b | get_swp_responder |

|    | password prep |
|----|---------------|
| 3a | pad_password |
| 3b | md5_password |
| 3c | ssl_password |

|    | cipher |
|----| -------|
| 4a | aes_ecb (encrypt) |
| 4b | aes_ctr (encrypt) |

## Tracking all completed searches

| align |         |           |     |       |     |
| B  N  | MSB bit | bit order | arg | pass p| ciph|
|-------|---------|-----------|-----|-------|-----|
|       |  73     |  ab       |  a  |  a    | a   | aaaa baaa
|       |  74     |  ab       |  ab |  ab   | ab  | aaaa baaa abaa bbaa aaba abba baba bbba aaab baab abab bbab
|       |  75     |  ab       |  ab |  ab   | ab  | aaaa baaa abaa bbaa aaba abba baba bbba aaab baab abab bbab
|    Y  |  76     |  ab       |  ab |  ab   | ab  | aaaa baaa abaa bbaa aaba abba baba bbba aaab baab abab bbab
|       |  77     |  ab       |  ab |  ab   | a   | aaaa baaa abaa bbaa aaba abba baba bbba
|       |  78     |  ab       |  ab |  ab   | a   | aaaa baaa abaa bbaa aaba abba baba bbba
| Y  Y  |  80     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|       |  83     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  |  84     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|       |  85     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  |  88     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  |  92     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  |  96     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 100     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 104     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 108     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 112     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 116     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 120     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 124     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 128     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 132     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 136     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 140     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 144     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 148     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 152     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 156     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 160     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 164     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 168     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 172     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 176     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 180     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 184     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|    Y  | 188     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
| Y  Y  | 192     | ab        |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|       | 193     |  ab       |  a  |  a    | a   | aaaa baaa
|       | 194     |  ab       |  ab |  ab   | a   | aaaa baaa abaa bbaa aaba abba baba bbba
|       | 195     |  ab       |  ab |  ab   | ab  | aaaa baaa abaa bbaa aaba abba baba bbba aaab baab abab bbab
|    Y  | 196     |  ab       |  ab |  ab   | ab  | aaaa baaa abaa bbaa aaba abba baba bbba aaab baab abab bbab
|       | 197     |  ab       |  ab |  ab   | ab  | aaaa baaa abaa bbaa aaba abba baba bbba aaab baab abab bbab
|       | 198     |  ab       |  ab |  ab   | a   | aaaa baaa abaa bbaa aaba abba baba bbba
| Y  Y  | 200     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                     aaab baab abab bbab
|       | 201     |  ab       |  ab |  ab   | a   | aaaa baaa abaa bbaa aaba abba baba bbba
|       | 202     |  ab       |  ab |  ab   | ab  | aaaa baaa abaa bbaa aaba abba baba bbba aaab baab abab bbab
|       | 203     |  ab       |   b |  ab   | ab  |           abaa bbaa aaba abba baba bbba aaab baab abab bbab
|    Y  | 204     |  ab       |  ab |  ab   | ab  | aaaa baaa abaa bbaa aaba abba baba bbba aaab baab abab bbab
|       | 205     |  ab       |  ab |  ab   | a   | aaaa baaa abaa bbaa aaba abba baba bbba
| Y  Y  | 208     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                      aaab baab abab bbab
|    Y  | 212     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                      aaab baab abab bbab
| Y  Y  | 216     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                      aaab baab abab bbab
|    Y  | 220     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                      aaab baab abab bbab
| Y  Y  | 224     |  ab       |  ab |  a    | ab  | aaaa baaa abaa bbaa                      aaab baab abab bbab
