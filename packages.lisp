;;; Package definitions

(defpackage #:aes
  (:use #:common-lisp)
  (:export #:aes-128 #:aes-192 #:aes-256
           #:encode #:decode)
  (:documentation "Advanced Encryption Standard (AES) encryption and decryption."))

(defpackage :aes-tests
  (:use #:common-lisp)
  (:documentation "AES tests"))
