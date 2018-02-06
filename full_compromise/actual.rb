#!/usr/bin/ruby

SampleCount = 100

def pulseValue(lines, center)
	peak = lines[center-1..center+1].inject(:+)/3

	low = center
	low -= 1 while (lines[low]-peak).abs < 0.1
	low += 1

	high = center
	high += 1 while (lines[high]-peak).abs < 0.1
	high -= 1

	width = high - low + 1
	raise if width < 30
	mean = lines[low..high].inject(:+) / width
	raise if (mean-peak).abs > 100

	return [mean, (low+high)/2]
end

begin
	if ARGV.count < 5 then
		puts "Usage: #{$0} <actual>.txt <start-offset> <end-offset> <gain> <baseline>"
		exit 1
	end

	lines = File::open(ARGV[0]).each_line.map{|x| x.to_f}
	start = ARGV[1].to_i
	last = ARGV[2].to_i
	width = (last-start) / 99.0
	gain = ARGV[3].to_i
	baseline = ARGV[4].to_i

	raise if start >= lines.count
	raise if last+20 >= lines.count

	puts "Parsing with width: %6.4f x%d"%[width, gain]

	pulses = []
	pulses << pulseValue(lines, start+width/2)
	99.times do
		pulses << pulseValue(lines, pulses.last[1]+width)
	end

	puts
	pulses.each_with_index do |p, i|
		(mean, center) = *p
		print "\t" if i%5==0
		print '%5d:%6.4f'%[center,mean]
		print ', ' if i%5!=4
		print "\n" if i%5==4
	end

	puts
	pulses.each_with_index do |p,i|
		x = p[0]*gain+baseline
		print "\t" if i%10==0
		print '%3x:%4d'%[x,x]
		print ', ' if i%10!=9
		print "\n" if i%10==9
	end
	puts
end

