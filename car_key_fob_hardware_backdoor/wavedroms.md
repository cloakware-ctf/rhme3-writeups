# detail

{signal: [
  {name: 'MOSI',     wave: 'x|..2|...xxx|.xx|xx4|..xxx|xxx', data: ['512 bit', '128 response', '128 bits', 'data']},
  {name: 'MISO',     wave: 'x|..x|.....3|..2|..2|..xx5|...', data: ['128 bit challenge', '256 bit', '128 bit', 'FLAG']},
  {},
  {name: 'CS/LATCH', wave: '1|0.1|...0.1|...|...|..0.1|...'},
  {name: 'CLK',      wave: 'p|.Pp|....Pp|...|...|...Pp|...'},
]}

# shorter

{signal: [
  {name: 'MOSI',     wave: 'x|..2|...xxx|.xx|4|..xxx|xxx', data: ['512 bit', '128 bit response', '128 bits', 'data']},
  {name: 'MISO',     wave: 'x|..x|.....3|..x|x|xxxx5|...', data: ['128 bit challenge', 'FLAG']},
  {},
  {name: 'CS/LATCH', wave: '1|0.1|...0.1|...|.|..0.1|...'},
  {name: 'CLK',      wave: 'p|.Pp|....Pp|...|.|...Pp|...'},
]}


# simplified

{signal: [
  {name: 'MOSI',     wave: 'x|..2|...x.2|.|...x.2|...x', data: ['512 bit', '512 bit', '384 bit']},
  {name: 'MISO',     wave: 'x|..2|...x.3|2|...x.2|...x', data: ['512 bit', '16B Chal.', '384 bit', '384 bit']},
  {},
  {name: 'CS/LATCH', wave: '1|0.1|...0.1|.|...0.1|...x'},
  {name: 'CLK',      wave: 'p|.Pp|....Pp|.|....Pp|...x'},
  {name: 'UART',     wave: '41.......................4'},
]}


