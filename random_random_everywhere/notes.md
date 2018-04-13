
## Random Random Everywhere
The security team is really motivated now. Now the device performs masking throughout the implementation. See if you can still extract the keys!

The device expects 18 bytes of input: the first byte should be either 0xAE (for encryption) or 0xAD (for decryption) followed by 16 bytes of data, followed by a newline.

## Initial Analysis
We think that the description means that every round is masked. In particular, they're probably using SBox masking. This sounds a job for second-order analysis...

To research:
	- Hamming Distance: difference between HW of previous operation and HW of this operation. Discards the "linear" model.

Finds:
http://www.win.tue.nl/~berry/papers/ches05hodpa.pdf
http://ieeexplore.ieee.org/document/6212441/

