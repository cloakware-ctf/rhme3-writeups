#!/usr/bin/ruby
## encoding: ASCII-8BIT

require 'pwn'

def waitForPrompt(prompt)
	buffer = ''
	loop do
		char = $serial.recvn 1, timeout:1
		buffer += char
		print char
		sleep 0.5 if char.empty?
		break if buffer =~ prompt
	end
end

# Harness
begin
	if ARGV.length < 1 then
		puts "Usage: #{$0} <port>"
		exit(1)
	end
	$serial = Pwnlib::Tubes::SerialTube.new ARGV[0], 115_200, false

	counter = [0]*256
		#(32..126).each do |c|
	10.times do
		100.times do |i|
			waitForPrompt /Please write your password: /
			$serial.send "q"*i
			print $serial.recvn i, timeout:3

			$serial.send "\n"
			t0 = Time.now
			char = $serial.recvn 2, timeout:3
			t1 = Time.now
			print char
			print $serial.recvline.chomp
			print " -- %8.6f\n"%[t1-t0]

			counter[i] += t1-t0
		end
	end

	256.times do |i|
		next if counter[i]==0
		puts '[%3d]: %9.6f'%[i, counter[i]]
	end

end

