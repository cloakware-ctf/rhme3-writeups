#!/usr/local/bin/rescue

require 'pwn'

SleepTime = 6.144

begin
	if ARGV.length < 2 then
		puts "Usage: #{$0} <port> <code>"
		exit(1)
	end

	port = ARGV[0]
	code = ARGV[1]
	if code.length != 250 then
		puts "WARNING! Code is #{code.length} characters."
	else
		puts "sending #{code.length} characters of passcode."
	end

	$serial = Pwnlib::Tubes::SerialTube.new port, 115_200, false

	puts "clearing init messages"
	$serial.recvpred(timeout:nil) { |data|
		data =~ /Type 'test' to run analog test.\r\n/
	}

	puts "sending data"
	$serial.send("*\n")
	print '0x'
	code.each_char do |char|
		$serial.send("."*char.ord)
		sleep SleepTime
		print '%02x'%[char.ord]
	end
	$serial.send("*")
	puts

	puts "getting reply"
	loop do
		char = $serial.recvn 1, timeout:1
		print char
		sleep 0.5 if char.empty?
	end
end

