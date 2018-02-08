#!/usr/local/bin/rescue

def align(left, right)
	# we hold 'left' still, and move 'right'
	# therefore moving from -right.length to left.length
	best = 100
	(-right.length..left.length).each do |offset|
		next if best.abs < offset.abs
		match = true
		left.each_char.each_with_index do |c,i|
			x = i + offset
			next if x < 0
			next if x >= right.length
			next if c==right[x]
			match = false
			break
		end
		best = offset if match
	end
	return best
end

begin
	if ARGV.count < 1 then
		puts "Usage: #{$0} <raw-bits>.txt"
		exit 1
	end
	lines = File::open(ARGV[0]).each_line.map{|x| x.chomp}.uniq

	loop do
		moreLines = []
		lines.each do |line1|
			lines.each do |line2|
				offset = align line1,line2
				# assert line1[i] = line2[i+offset] for all i in range
				if 0 < offset && offset <= 1
					then
					lines -= [line1, line2]
					moreLines << line2[0...offset] + line1
				elsif 0 < offset && offset <= -1 then
					lines -= [line1, line2]
					moreLines << line1 + line2[offset..-1]
				end
			end
		end
		break if moreLines.empty?
		lines += moreLines
		lines.uniq!
	end

	raise
end
