;;;; Package definitions

(defpackage :aes
  (:use #:common-lisp)
  (:export #:aes-128 #:aes-192 #:aes-256
           #:encrypt #:decrypt
 	   #:block-encrypt-ecb #:block-decrypt-ecb
 	   #:block-encrypt-cbc #:block-decrypt-cbc)
  (:documentation "Advanced Encryption Standard (AES) encryption and decryption."))
