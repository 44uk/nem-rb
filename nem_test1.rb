require './ed25519.rb'
require 'openssl'
require 'digest/sha3'

seed = '11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff'

# unhexlify and reverse
sk = seed.scan(/../).map(&:hex).reverse.pack('C*')

sha512   = Proc.new {|m| OpenSSL::Digest::SHA512.digest(m) }
sha3_512 = Proc.new {|m| Digest::SHA3.digest(m) }

pk0 = publickey_unsafe(sk)
pk1 = publickey_hash_unsafe(sk, sha512)
pk2 = publickey_hash_unsafe(sk, sha3_512)

puts "          sec key: #{sk.unpack('H*').first}"
puts "VALID NEM pub key: #{pk2.unpack('H*').first}"
puts '-'*80

puts 'NOT valid NEM pub keys produced by original ed25519'
puts "v1: #{pk0.unpack('H*').first}"
puts "v2: #{pk1.unpack('H*').first}"

