require './ed25519.rb'
require 'base32'
require 'digest/sha3'
require 'openssl'

class Account
  attr_reader :pk, :sk, :hex_public_key, :hex_priv_key, :address

  @@sha3_512 = Proc.new {|m| Digest::SHA3.digest(m) }
  @@sha3_256 = Proc.new {|m| Digest::SHA3.digest(m, 256) }

  def initialize(hex_priv_key, network = :mainnet)
    @hex_priv_key = hex_priv_key
    @network = network

    calculate_key_pair
    calculate_address
  end

  def sign(bin_message)
    signature_hash_unsafe(bin_message, @sk, @pk, sha3_512)
  end

  private

  def calculate_key_pair
    @sk = @hex_priv_key.scan(/../).map(&:hex).reverse.pack('C*')
    @pk = publickey_hash_unsafe(@sk, sha3_512)

    @hex_public_key = @pk.unpack('H*').first
  end

  def calculate_address
    pubkey = @pk
    sha3_pubkey = sha3_256.call(pubkey)
    ripe = OpenSSL::Digest::RIPEMD160.digest(sha3_pubkey)

    if @network == :testnet
      version = "\x98" + ripe
    else
      version = "\x68" + ripe
    end

    checksum = sha3_256.call(version)[0...4]
    @address = Base32.encode(version + checksum)
  end

  def verify(hexed_message)
    # TODO: not implemented
  end

  def sha3_256
    @@sha3_256
  end

  def sha3_512
    @@sha3_512
  end
end
