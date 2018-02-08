#!/usr/bin/ruby
# encoding: ASCII-8BIT


Byte_102a6b = Array.new(100) { Random::rand 256 }
Debug = false
$randomizer = Random::rand(100)

def predict(i, grid1, grid2)
	result = [grid1, grid2][i%2][i/2]
	result = (result * 2730.0 / 100.0).to_i + 0x2aa

	return result if (i<50 || i%5!=0)

	if (Byte_102a6b[$randomizer] % 2 == 0) then
		#result -= 0x2aa
	else
		#result += 0x2aa
	end
	$randomizer = ($randomizer+1)%100

	return result
end

def extractGrids(hexFile)
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
	low = words[_reset+0xf]
	high = words[_reset+0xf+1]
	data = (high << 4 & 0xf000) + (high << 8 & 0xf00) + (low >> 4 & 0xf0) + (low >> 0 & 0xf)
	offset = 10
	offset += 1 if bytes[data] != 0x12

	Debug && puts("Reading data from #{data.to_s 16}/#{(data/2).to_s 16} at #{offset}")
	Debug && puts("First bytes #{bytes[data].to_s 16}, #{bytes[data,8]}")
	Debug && puts("Relevant bytes #{bytes[data+offset,8]}")
	Debug && puts("Total sizes #{bytes.count.to_s 16}")
	return bytes[data+offset..-1].each_slice(298).first(4)
end

begin
	if ARGV.count < 2 || ARGV[1]!='test' && ARGV[1]!='risc' then
		puts "Usage: #{$0} <sample>.hex {test|risc}"
		exit 1
	else
	end

	grids = extractGrids ARGV[0]
	base = ARGV[1]=='test' ? 0 : 2

	predictions = 100.times.map do |x|
		predict x, grids[base+0], grids[base+1]
	end

	puts
	predictions.each_with_index do |x,i|
		print "\t" if i%10==0
		print '%3x:%4d'%[x,x]
		print ', ' if i%10!=9
		print "\n" if i%10==9
	end
	puts
end

