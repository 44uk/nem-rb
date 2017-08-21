NEM-rb
=======

The ruby version of NEM-py.

- [NemProject/nem-py](https://github.com/NemProject/nem-py)

Setup
------

```
gem install digest-sha3
gem install base32
```

Verification test vectors
------

- [NemProject/nem-test-vectors](https://github.com/NemProject/nem-test-vectors)

```
# example
ruby test_nem_vectors.rb  --test-sha3-256-file ../nem-test-vectors/0.test-sha3-256.dat
ruby test_nem_vectors.rb  --test-keys-file ../nem-test-vectors/1.test-keys.dat
ruby test_nem_vectors.rb  --test-sign-file ../nem-test-vectors/2.test-sign.dat
```

