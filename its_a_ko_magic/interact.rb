#!/usr/bin/ruby
# encoding: ASCII-8BIT

require 'pwn'

def serial_send(byte, msg)
	if byte.length != 1 then
		puts "arg0 must be a 1 byte string."
		return
	elsif msg.length != 16 then
		puts "Only works on 16 byte messages."
		return
	end

	$serial.send byte
	$serial.send msg
	$serial.send "\n"
	puts hexdump $serial.recvline

	puts "Result:"
	result = $serial.read 20
	puts hexdump result
	return result
end
def decrypt(msg)
	puts "Decrypting:"
	return serial_send("\xAD", msg)
	puts
	puts
end
def encrypt(msg)
	puts "Encrypting:"
	return serial_send("\xAE", msg)
	puts
	puts
end

begin
	if ARGV.length < 1 then
		puts "Usage: #{$0} <port>"
		exit(1)
	else
		$serial = Pwnlib::Tubes::SerialTube.new ARGV[0], 115_200, false
	end

	plain = (0..15).map{|x| x.to_s 16}.join
	cipher = encrypt plain
	out = decrypt cipher
end
