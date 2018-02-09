#!/usr/bin/ruby
# encoding: ASCII-8BIT

begin
	if ARGV.count < 1 then
		puts "Usage: #{$0} <bitdump>"
		exit 1
	else
	end

	bytes = File::open(ARGV[0]).each_byte.to_a
	hundred = bytes[11...111]

	raise unless bytes.count == 128
	raise unless hundred.count == 100
	raise unless bytes[0...11].all? {|x| x==0}
	raise unless bytes[111..-1].all? {|x| x==0}

	print "#{ARGV[0]}: "
	puts hundred.map{|x| (x%2).to_i}.join
end

