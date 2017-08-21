require 'optparse'
require 'digest/sha3'
require './ed25519.rb'
require './account.rb'

opt = OptionParser.new

def hexlify(obj)
  obj.unpack('H*').first
end

def unhexlify(obj)
  obj.scan(/../).map(&:hex).pack('C*')
end

def verify_sha3_256(line)
  re = /^: ([0-9a-f]+) : ([0-9]{2,3}) : ([0-9a-f]+)$/
  res = re.match(line)
  return false unless res

  expected_hash = unhexlify(res[1])
  data_length = res[2].to_i
  data = unhexlify(res[3])
  raise unless data.size == data_length

  computed_hash = Digest::SHA3.digest(data, 256)
  if computed_hash == expected_hash
    return true
  else
    puts 'Failed hash:'
    puts "  computed: hexlify(computed_hash)"
    puts "  expected: hexlify(expected_hash)"
    return false
  end
end

def verify_key(line)
  re = /^: ([a-f0-9]+) : ([a-f0-9]+) : ([a-f0-9]+) : ([A-Z2-7]+)$/
  res = re.match(line)
  return false unless res

  private_key_hex = res[1]
  expected_public = unhexlify(res[3])
  expected_address = res[4]

  account = Account.new(private_key_hex)
  if account.pk == expected_public
    if account.address == expected_address
      return true
    else
      puts 'Failed when calculating address:'
      puts "  computed address: #{account.address}"
      puts "  expected address: #{expected_address}"
      return false
    end
  else
    puts 'Failed public from private:'
    puts "  computed public: #{hexlify accountp.pk}"
    puts "  expected public: #{hexlify expected_public}"
    return false
  end
end

def verify_sign(line)
  re = /: ([a-f0-9]+) : ([a-f0-9]+) : ([a-f0-9]+) : ([0-9]{2}) : ([a-f0-9]+)$/
  res = re.match(line)
  return false unless res

  private_key_hex = res[1]
  expected_public = unhexlify(res[2])
  expected_signature = unhexlify(res[3])
  data_length = res[4].to_i
  data = unhexlify(res[5])
  raise unless data.size == data_length

  account = Account.new(private_key_hex)
  if account.pk == expected_public
    computed_signature = account.sign(data)
    if computed_signature == expected_signature
      return true
    else
      puts 'Failed when calculating signature:'
      puts "  computed signature: #{hexlify(computed_signature)}"
      puts "  expected signature: #{hexlify(expected_signature)}"
      return false
    end
  else
    puts 'Failed public from private:'
    puts "  computed public: #{hexlify(account.pk)}"
    puts "  expected public: #{hexlify(expected_public)}"
    return false
  end
end

def test_file(filename, cbfunc)
  File.open(filename) do |f|
    c = 0
    f.each_line do |line|
      line.strip!
      next if line.start_with?('#')
      unless cbfunc.call(line)
        c = 0
        break
      end
      c += 1
      puts "test: #{c}" if (c % 31) == 0
    end
    puts "#{c} PASSED" if c > 0
  end
end

opt.on('--test-sha3-256-file filename', 'test sha3 implementation') do |v|
  test_file(v, Proc.new {|l| verify_sha3_256(l) })
end

opt.on('--test-keys-file filename', 'test public and address generation') do |v|
  test_file(v, Proc.new {|l| verify_key(l) })
end

opt.on('--test-sign-file filename', 'test signing') do |v|
  test_file(v, Proc.new {|l| verify_sign(l) })
end

opt.parse!(ARGV)
