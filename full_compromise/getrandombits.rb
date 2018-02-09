#!/usr/bin/ruby
# encoding: ASCII-8BIT
#!/usr/local/bin/rescue

Debug = true

def findGenRandomBits(hexFile)
	file = File::open(ARGV[0]).each_line.map do |line|
		line[9..40]
	end
	words = file.join.scan(/..../).map do |hex|
		(hex[2..3] + hex[0..1]).to_i(16)
	end
	bytes = file.join.scan(/../).map do |hex|
		hex[0..1].to_i(16)
	end

	_reset = words[1]
	callMain = words[_reset+0x22,2]
	raise unless callMain[0] == 0x940e   # call
	main = callMain[1]
	raise unless [0x9508,0x9518].include? words[main-1] # ret, reti
	Debug && puts('main() found at %04x'%[main])

	callDoTest = words[main+0x169,2]
	raise unless callDoTest[0] == 0x940e   # call
	test = callDoTest[1]
	raise unless [0x9508,0x9518].include? words[test-1] # ret, reti
	Debug && puts('do_test() found at %04x'%[test])

	callGenRandom = words[test+0x9,2]
	raise unless callGenRandom[0] == 0x940e   # call
	genRandom = callGenRandom[1]
	raise unless [0x9508,0x9518].include? words[genRandom-1] # ret, reti
	Debug && puts('gen_random_bits() found at %04x'%[genRandom])

	return test+0x9
end

def dumpBits(file, sampleNumber, address)
	pid = fork do
		exec "/home/jonathan.beverley/Programs/simavr/simavr/obj-x86_64-linux-gnu/run_avr.elf -m atmega1280 -f 32000000 -g #{file}"
	end

	hexAddr = '0x%04x'%[2*address]
	gdb = "avr-gdb -batch -nx"                    \
			" -ex 'target remote localhost:1234'" \
			" -ex 'set $pc = #{hexAddr}'"         \
			" -ex 'break *($pc+4)'"               \
			" -ex 'cont'"                         \
			" -ex 'dump binary memory bitdump#{sampleNumber} 0x2a60 0x2ae0'"
	system(gdb)
	Process.kill 'TERM', pid
end

begin
	if ARGV.count < 1 then
		puts "Usage: #{$0} <sample>.hex"
		exit 1
	else
	end

	sampleNumber = ARGV[0].gsub(/.*sample([0-9]+)\.hex/, '\1')
	address = findGenRandomBits ARGV[0]
	Debug && puts('Sample[%d]: %04x'%[sampleNumber, address])

	dumpBits ARGV[0], sampleNumber, address
end

