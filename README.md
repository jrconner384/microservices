# microservices

My first Functions app just computes the HMAC SHA256 hash as a hex string.
I figured I'd group this kind of experimental work in a microservices repo,
since I'm not necessarily looking at creating a bit thing orbiting this
hash thing.

# Buyer beware

This is not a secure implementation yet. It expects the private key used
in computing the hash to be passed as a header in the HTTP request.
