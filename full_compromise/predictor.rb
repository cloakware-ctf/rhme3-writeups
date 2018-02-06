#!/usr/local/bin/rescue

Byte_102a6b = Array.new(100) { Random::rand 256 }
$randomizer = Random::rand(100)

def predict(i, grid1, grid2)
	result = [grid1, grid2][i%2][i/2]
	result = (result * 2730.0 / 100.0).to_i + 0x2aa

	return result if (i<50 || i%5!=0)
	r24 = 0x81 & Byte_102a6b[$randomizer]
	r24 = ((r24-1) | 0xfe) + 1 if (r24&0x80)
	if (Byte_102a6b[$randomizer] % 2) then
		result -= 0x2aa
	else
		result += 0x2aa
	end

	$randomizer = ($randomizer+1)%100
end

def extractGrids(hexFile)
	file = ARGF.each_line.map do |line|
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

	return bytes[data+11..-1].each_slice(298).first(4)
end

begin
	if ARGV.count < 1 then
		puts "Usage: #{$0} <sample>.hex"
		exit 1
	end

	grids = extractGrids ARGF

	predictions = 100.times.map do |x|
		predict x, grids[2], grids[3]
	end

	p predictions.map{|x| '%04x'%x}
end

