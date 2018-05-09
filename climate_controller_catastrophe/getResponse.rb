#!/usr/bin/ruby

# Extended Euclidean algorithm
def egcd(a, b)
    if a == 0 then
        return [b, 0, 1]
    else
        (g, y, x) = egcd(b % a, a)
        return [g, x - (b / a) * y, y]
    end
end

# Modular inverse
def modInv(a, m)
    (gcd, x, y) = egcd(a%m, m)
    if gcd != 1 then
        return nil  # modular inverse does not exist
    else
        return x % m
    end
end

# Modular power
def modPower(x, exp, mod)
    # Alternately, use openssl
    # require 'openssl'
    # puts a.to_bn.mod_exp(b, m)
    raise(ArgumentError, "negative exponent") if exp<0
    prod = 1
    base = x % mod
    until exp.zero?
        exp.odd? and prod = (prod * base) % mod
        exp >>= 1
        base = (base * base) % mod
    end
    prod
end

Exponent = 31337
Modulus = 2777704703
Phi = 2777595240

begin
	if ARGV.length < 1 then
		puts "Usage: #{$0} <challenge>"
		exit 1
	end

	# challenge = ARGV[0].to_i
	challenge = ARGV.reverse.join.to_i(16)

	phi = modInv(Exponent, Phi)
	response = modPower(challenge, phi, Modulus)
	raise 'end check failed' unless challenge == modPower(response, Exponent, Modulus)
	#puts ('%016x'%[response]).scan(/../).reverse.join
	puts ('%08x'%[response]).scan(/../).reverse.join
end

