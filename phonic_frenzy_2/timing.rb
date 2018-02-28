#!/usr/local/bin/rescue

require 'pwn'

# Harness
begin
	if ARGV.length < 1 then
		puts "Usage: #{$0} <port>"
		exit(1)
	end

	port = ARGV[0]
	$location = nil
	$serial = Pwnlib::Tubes::SerialTube.new port
	#$conn = Pwnlib::Tubes::Sock.new 'localhost', 10233

	startTime = Time.now

	while (true) do
		line = $serial.gets()
		next if line.chomp.empty?

		if line =~ /Welcome to the Infotainment Center./  then
			puts
			startTime = Time.now
		end
		deltaTime = Time.now - startTime
		puts " %7.4f: %s"%[deltaTime, line.gsub(/\n/, ' ')]
	end
end

