#!/usr/local/bin/pry

require 'pwn'

def deg2rad(deg)
	return deg * Math::PI / 180
end

def findLL(latitude)
	a = 6378.1370
	b = 6356.7523142
	e = Math::sqrt((a*a - b*b) / (a*a))
	lat = deg2rad(latitude)

	numerator = (Math::PI * a * Math::cos(lat))
	denominator = 180 * Math::sqrt(1 - e*e*(Math::sin(lat)**2))
	long = numerator/denominator
end

def vector(from, to)
	dX = (to[0] - from[0])
	dY = (to[1] - from[1])
	dX = dX % 360 if (dX%360).abs < dX.abs
	dY = dY % 360 if (dY%360).abs < dY.abs
	return [dX,dY]
end

def distance(from, to)
	# we assume a degree of latitude is 111.7km
	latLength = 111.7 # km
	longLength = findLL(from[0])

	delta = vector(from, to)

	dXkm = delta[0]*latLength
	dYkm = delta[1]*longLength

	return Math::sqrt(dXkm**2 + dYkm**2)
end

def oneStep(from, to, speed=$carSpeed)
	delta = vector(from, to)

	dH = distance(from, to)
	return to if dH < speed
	scale = speed / dH

	step = [from[0]+delta[0]*scale, from[1]+delta[1]*scale]
	step[0] += 360 if step[0] <= -180
	step[0] += 360 if step[0] <= -180
	step[1] -= 360 if step[1] >= 180
	step[1] -= 360 if step[1] >= 180
	return step
end

def printStep(pos)
	return "%9.6f  %9.6f" % [pos[0],pos[1]]
end

def findPath(origin, destination, speed)
	path = []
	current = origin
	loop do
		step = oneStep(current, destination, speed)
		path << step
		current = step
		break if current==destination
	end
	return path
end

def findPathTo(destination, speed=$carSpeed)
	return findPath($location, destination, speed)
end

def walkStep(step)
	$serial.sendline "%9.6f  %9.6f" % step
	$history << $location
	$location = step
	input = $serial.recvpred(timeout:2) { |data|
		result = false
		result = true if data =~ /\n> /
		result = true if data =~ /==END==/
		result
	}
	return processInput input
end

def walkPath(path)
	path.each do |step|
		return false unless walkStep(step)
	end
	return true
end

$planeSpeed = 655.0
def fly(destination)
	walkPath findPathTo(destination, $planeSpeed)
end

$carSpeed = 99.0
def drive(destination)
	walkPath findPathTo(destination, $carSpeed)
end

$boatSpeed = 30.0
def sail(destination)
	walkPath findPathTo(destination, $boatSpeed)
end

$buffer=nil
$history=[]
def processInput(input)
	puts input
	$buffer = input
	lines = input.split("\n")
	lines.each do |line|
		case line
		when /Latitude/
			parts = line.split("\t")
			lat  = parts.first.split.last.to_f
			long = parts.last .split.last.to_f
			old = $location
			$location = [lat,long]
			puts "New location: #{$location}"
			puts "old was: #{old}"
		when /Location: /
			parts = line.split
			$destination = parts[1..2].map{|x| x.to_f}
			puts "New destination: #{$destination}"
			return nil
		when /Enter your name to start/
			$history = []
			$serial.sendline "Go Go Go Bot"
		when /==END==/
			puts "busted, fail."
			return nil
		end
	end
	puts "Time: #{$history.length}h"
	return $location
end

def status()
	processInput $serial.read(5000, timeout:1)
	return $location
end

# Local Utility:
Office = [51.9979258, 4.3834606] # Riscure Head Office, aka Delft
RNA = [37.7932696,-122.4065417] # Riscure North America


CDG = [49.0096906, 2.5457305]
SFO = [37.6213129, -122.3811494]
PVG = [31.1443439, 121.806079]
Shanghai = [31.2231281,120.9149854]

def leg1()
	drive(Office)
end
def leg2()
	drive(CDG) && fly(PVG) && drive(Shanghai) && sail($destination)
end
def leg3()
	sail(Shanghai) && drive(PVG) && fly(SFO) && drive(RNA)
end
def leg4()
	drive(SFO) && fly(CDG) && drive(Office)
end

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

	status()
	puts "we are in"
	binding.pry
	puts "we are out"
end

