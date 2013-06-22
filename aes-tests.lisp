;;; AES tests

(in-package #:aes-tests)

;;; FIPS-197: Appendix A - Key Expansion Examples

(sb-rt:deftest aes.key-expansion-128
    (let ((aes-128 (make-instance 'aes:aes-128 :cipher-key #x2b7e151628aed2a6abf7158809cf4f3c)))
      (and (= (aref (slot-value aes-128 'aes::expanded-keys)  0) #x2b7e151628aed2a6abf7158809cf4f3c)
	   (= (aref (slot-value aes-128 'aes::expanded-keys)  1) #xa0fafe1788542cb123a339392a6c7605)
	   (= (aref (slot-value aes-128 'aes::expanded-keys)  2) #xf2c295f27a96b9435935807a7359f67f)
	   (= (aref (slot-value aes-128 'aes::expanded-keys)  3) #x3d80477d4716fe3e1e237e446d7a883b)
	   (= (aref (slot-value aes-128 'aes::expanded-keys)  4) #xef44a541a8525b7fb671253bdb0bad00)
	   (= (aref (slot-value aes-128 'aes::expanded-keys)  5) #xd4d1c6f87c839d87caf2b8bc11f915bc)
	   (= (aref (slot-value aes-128 'aes::expanded-keys)  6) #x6d88a37a110b3efddbf98641ca0093fd)
	   (= (aref (slot-value aes-128 'aes::expanded-keys)  7) #x4e54f70e5f5fc9f384a64fb24ea6dc4f)
	   (= (aref (slot-value aes-128 'aes::expanded-keys)  8) #xead27321b58dbad2312bf5607f8d292f)
	   (= (aref (slot-value aes-128 'aes::expanded-keys)  9) #xac7766f319fadc2128d12941575c006e)
	   (= (aref (slot-value aes-128 'aes::expanded-keys) 10) #xd014f9a8c9ee2589e13f0cc8b6630ca6)))
  t)

(sb-rt:deftest aes.key-expansion-192
    (let ((aes-192 (make-instance 'aes:aes-192 :cipher-key #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b)))
      (and (= (aref (slot-value aes-192 'aes::expanded-keys)  0) #x8e73b0f7da0e6452c810f32b809079e5)
	   (= (aref (slot-value aes-192 'aes::expanded-keys)  1) #x62f8ead2522c6b7bfe0c91f72402f5a5)
	   (= (aref (slot-value aes-192 'aes::expanded-keys)  2) #xec12068e6c827f6b0e7a95b95c56fec2)
	   (= (aref (slot-value aes-192 'aes::expanded-keys)  3) #x4db7b4bd69b5411885a74796e92538fd)
	   (= (aref (slot-value aes-192 'aes::expanded-keys)  4) #xe75fad44bb095386485af05721efb14f)
	   (= (aref (slot-value aes-192 'aes::expanded-keys)  5) #xa448f6d94d6dce24aa326360113b30e6)
	   (= (aref (slot-value aes-192 'aes::expanded-keys)  6) #xa25e7ed583b1cf9a27f939436a94f767)
	   (= (aref (slot-value aes-192 'aes::expanded-keys)  7) #xc0a69407d19da4e1ec1786eb6fa64971)
	   (= (aref (slot-value aes-192 'aes::expanded-keys)  8) #x485f703222cb8755e26d135233f0b7b3)
	   (= (aref (slot-value aes-192 'aes::expanded-keys)  9) #x40beeb282f18a2596747d26b458c553e)
	   (= (aref (slot-value aes-192 'aes::expanded-keys) 10) #xa7e1466c9411f1df821f750aad07d753)
	   (= (aref (slot-value aes-192 'aes::expanded-keys) 11) #xca4005388fcc5006282d166abc3ce7b5)
	   (= (aref (slot-value aes-192 'aes::expanded-keys) 12) #xe98ba06f448c773c8ecc720401002202)))
  t)

(sb-rt:deftest aes.key-expansion-256
    (let ((aes-256 (make-instance 'aes:aes-256 :cipher-key #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4)))
      (and (= (aref (slot-value aes-256 'aes::expanded-keys)  0) #x603deb1015ca71be2b73aef0857d7781)
	   (= (aref (slot-value aes-256 'aes::expanded-keys)  1) #x1f352c073b6108d72d9810a30914dff4)
	   (= (aref (slot-value aes-256 'aes::expanded-keys)  2) #x9ba354118e6925afa51a8b5f2067fcde)
	   (= (aref (slot-value aes-256 'aes::expanded-keys)  3) #xa8b09c1a93d194cdbe49846eb75d5b9a)
	   (= (aref (slot-value aes-256 'aes::expanded-keys)  4) #xd59aecb85bf3c917fee94248de8ebe96)
	   (= (aref (slot-value aes-256 'aes::expanded-keys)  5) #xb5a9328a2678a647983122292f6c79b3)
	   (= (aref (slot-value aes-256 'aes::expanded-keys)  6) #x812c81addadf48ba24360af2fab8b464)
	   (= (aref (slot-value aes-256 'aes::expanded-keys)  7) #x98c5bfc9bebd198e268c3ba709e04214)
	   (= (aref (slot-value aes-256 'aes::expanded-keys)  8) #x68007bacb2df331696e939e46c518d80)
	   (= (aref (slot-value aes-256 'aes::expanded-keys)  9) #xc814e20476a9fb8a5025c02d59c58239)
	   (= (aref (slot-value aes-256 'aes::expanded-keys) 10) #xde1369676ccc5a71fa2563959674ee15)
	   (= (aref (slot-value aes-256 'aes::expanded-keys) 11) #x5886ca5d2e2f31d77e0af1fa27cf73c3)
	   (= (aref (slot-value aes-256 'aes::expanded-keys) 12) #x749c47ab18501ddae2757e4f7401905a)
	   (= (aref (slot-value aes-256 'aes::expanded-keys) 13) #xcafaaae3e4d59b349adf6acebd10190d)
	   (= (aref (slot-value aes-256 'aes::expanded-keys) 14) #xfe4890d1e6188d0b046df344706c631e)))
  t)

;;; FIPS-197: Appendix C - Example Vectors

(sb-rt:deftest aes.encode-128
    (let ((aes-128 (make-instance 'aes:aes-128 :cipher-key #x000102030405060708090a0b0c0d0e0f)))
      (aes:encode aes-128 #x00112233445566778899aabbccddeeff))
  #x69c4e0d86a7b0430d8cdb78070b4c55a)

(sb-rt:deftest aes.decode-128
    (let ((aes-128 (make-instance 'aes:aes-128 :cipher-key #x000102030405060708090a0b0c0d0e0f)))
      (aes:decode aes-128 #x69c4e0d86a7b0430d8cdb78070b4c55a))
  #x00112233445566778899aabbccddeeff)

(sb-rt:deftest aes.encode-192
    (let ((aes-192 (make-instance 'aes:aes-192 :cipher-key #x000102030405060708090a0b0c0d0e0f1011121314151617)))
      (aes:encode aes-192 #x00112233445566778899aabbccddeeff))
  #xdda97ca4864cdfe06eaf70a0ec0d7191)

(sb-rt:deftest aes.decode-192
    (let ((aes-192 (make-instance 'aes:aes-192 :cipher-key #x000102030405060708090a0b0c0d0e0f1011121314151617)))
      (aes:decode aes-192 #xdda97ca4864cdfe06eaf70a0ec0d7191))
  #x00112233445566778899aabbccddeeff)

(sb-rt:deftest aes.encode-256
    (let ((aes-256 (make-instance 'aes:aes-256 :cipher-key #x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)))
      (aes:encode aes-256 #x00112233445566778899aabbccddeeff))
  #x8ea2b7ca516745bfeafc49904b496089)

(sb-rt:deftest aes.decode-256
    (let ((aes-256 (make-instance 'aes:aes-256 :cipher-key #x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)))
      (aes:decode aes-256 #x8ea2b7ca516745bfeafc49904b496089))
  #x00112233445566778899aabbccddeeff)
