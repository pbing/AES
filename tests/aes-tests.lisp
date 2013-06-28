;;; AES tests

(in-package #:aes-tests)

;;; FIPS-197: Appendix A - Key Expansion Examples

(sb-rt:deftest key-expansion-128
    (let ((aes-128 (make-instance 'aes:aes-128 :cipher-key #x2b7e151628aed2a6abf7158809cf4f3c)))
      (and (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  0) #(#x2b7e1516 #x28aed2a6 #xabf71588 #x09cf4f3c))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  1) #(#xa0fafe17 #x88542cb1 #x23a33939 #x2a6c7605))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  2) #(#xf2c295f2 #x7a96b943 #x5935807a #x7359f67f))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  3) #(#x3d80477d #x4716fe3e #x1e237e44 #x6d7a883b))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  4) #(#xef44a541 #xa8525b7f #xb671253b #xdb0bad00))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  5) #(#xd4d1c6f8 #x7c839d87 #xcaf2b8bc #x11f915bc))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  6) #(#x6d88a37a #x110b3efd #xdbf98641 #xca0093fd))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  7) #(#x4e54f70e #x5f5fc9f3 #x84a64fb2 #x4ea6dc4f))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  8) #(#xead27321 #xb58dbad2 #x312bf560 #x7f8d292f))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys)  9) #(#xac7766f3 #x19fadc21 #x28d12941 #x575c006e))
	   (equalp (aref (slot-value aes-128 'aes::expanded-encryption-keys) 10) #(#xd014f9a8 #xc9ee2589 #xe13f0cc8 #xb6630ca6))))
  t)

(sb-rt:deftest key-expansion-192
    (let ((aes-192 (make-instance 'aes:aes-192 :cipher-key #x8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b)))
      (and (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  0) #(#x8e73b0f7 #xda0e6452 #xc810f32b #x809079e5))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  1) #(#x62f8ead2 #x522c6b7b #xfe0c91f7 #x2402f5a5))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  2) #(#xec12068e #x6c827f6b #x0e7a95b9 #x5c56fec2))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  3) #(#x4db7b4bd #x69b54118 #x85a74796 #xe92538fd))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  4) #(#xe75fad44 #xbb095386 #x485af057 #x21efb14f))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  5) #(#xa448f6d9 #x4d6dce24 #xaa326360 #x113b30e6))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  6) #(#xa25e7ed5 #x83b1cf9a #x27f93943 #x6a94f767))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  7) #(#xc0a69407 #xd19da4e1 #xec1786eb #x6fa64971))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  8) #(#x485f7032 #x22cb8755 #xe26d1352 #x33f0b7b3))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys)  9) #(#x40beeb28 #x2f18a259 #x6747d26b #x458c553e))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys) 10) #(#xa7e1466c #x9411f1df #x821f750a #xad07d753))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys) 11) #(#xca400538 #x8fcc5006 #x282d166a #xbc3ce7b5))
	   (equalp (aref (slot-value aes-192 'aes::expanded-encryption-keys) 12) #(#xe98ba06f #x448c773c #x8ecc7204 #x01002202))))
  t)

(sb-rt:deftest key-expansion-256
    (let ((aes-256 (make-instance 'aes:aes-256 :cipher-key #x603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4)))
      (and (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  0) #(#x603deb10 #x15ca71be #x2b73aef0 #x857d7781))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  1) #(#x1f352c07 #x3b6108d7 #x2d9810a3 #x0914dff4))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  2) #(#x9ba35411 #x8e6925af #xa51a8b5f #x2067fcde))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  3) #(#xa8b09c1a #x93d194cd #xbe49846e #xb75d5b9a))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  4) #(#xd59aecb8 #x5bf3c917 #xfee94248 #xde8ebe96))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  5) #(#xb5a9328a #x2678a647 #x98312229 #x2f6c79b3))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  6) #(#x812c81ad #xdadf48ba #x24360af2 #xfab8b464))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  7) #(#x98c5bfc9 #xbebd198e #x268c3ba7 #x09e04214))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  8) #(#x68007bac #xb2df3316 #x96e939e4 #x6c518d80))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys)  9) #(#xc814e204 #x76a9fb8a #x5025c02d #x59c58239))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys) 10) #(#xde136967 #x6ccc5a71 #xfa256395 #x9674ee15))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys) 11) #(#x5886ca5d #x2e2f31d7 #x7e0af1fa #x27cf73c3))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys) 12) #(#x749c47ab #x18501dda #xe2757e4f #x7401905a))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys) 13) #(#xcafaaae3 #xe4d59b34 #x9adf6ace #xbd10190d))
	   (equalp (aref (slot-value aes-256 'aes::expanded-encryption-keys) 14) #(#xfe4890d1 #xe6188d0b #x046df344 #x706c631e))))
  t)

;;; FIPS-197: Appendix C - Example Vectors

(sb-rt:deftest encrypt-128
    (let ((aes-128 (make-instance 'aes:aes-128 :cipher-key #x000102030405060708090a0b0c0d0e0f)))
      (aes:encrypt aes-128 #x00112233445566778899aabbccddeeff))
  #x69c4e0d86a7b0430d8cdb78070b4c55a)

(sb-rt:deftest decrypt-128
    (let ((aes-128 (make-instance 'aes:aes-128 :cipher-key #x000102030405060708090a0b0c0d0e0f)))
      (aes:decrypt aes-128 #x69c4e0d86a7b0430d8cdb78070b4c55a))
  #x00112233445566778899aabbccddeeff)

(sb-rt:deftest encrypt-192
    (let ((aes-192 (make-instance 'aes:aes-192 :cipher-key #x000102030405060708090a0b0c0d0e0f1011121314151617)))
      (aes:encrypt aes-192 #x00112233445566778899aabbccddeeff))
  #xdda97ca4864cdfe06eaf70a0ec0d7191)

(sb-rt:deftest decrypt-192
    (let ((aes-192 (make-instance 'aes:aes-192 :cipher-key #x000102030405060708090a0b0c0d0e0f1011121314151617)))
      (aes:decrypt aes-192 #xdda97ca4864cdfe06eaf70a0ec0d7191))
  #x00112233445566778899aabbccddeeff)

(sb-rt:deftest encrypt-256
    (let ((aes-256 (make-instance 'aes:aes-256 :cipher-key #x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)))
      (aes:encrypt aes-256 #x00112233445566778899aabbccddeeff))
  #x8ea2b7ca516745bfeafc49904b496089)

(sb-rt:deftest decrypt-256
    (let ((aes-256 (make-instance 'aes:aes-256 :cipher-key #x000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f)))
      (aes:decrypt aes-256 #x8ea2b7ca516745bfeafc49904b496089))
  #x00112233445566778899aabbccddeeff)
