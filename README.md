# chacha20blake2s

A small construction of chacha20 with blake2s as the HMAC.  
This was made primarily for fun, and so should not be put into production unless you really trust me.  
  
This is motivated by my reading about partitioning oracle attacks, and how AES-poly1305 and chacha20poly1305 constructs are vulnerable to them.  
  
https://www.usenix.org/system/files/sec21summer_len.pdf
  
Plus I couldnt find an easy already made library for it.