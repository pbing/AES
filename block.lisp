;;;; Block encryption/decryption

(in-package #:aes)

;;; Mode: ECB - Electronic Codebook
(defgeneric block-encrypt-ecb (o plain-text cipher-text))
(defmethod block-encrypt-ecb (o plain-text cipher-text)
  "AES encryption with Electronic Codebook (ECB) mode of array
PLAN-TEXT. Result is array CIPHER-TEXT."
  (loop for i below (length plain-text) do
    (setf (aref cipher-text i) (encrypt o (aref plain-text i))))
  cipher-text)

(defgeneric block-decrypt-ecb (o cipher-text plain-text))
(defmethod block-decrypt-ecb (o cipher-text plain-text)
  "AES decryption with Electronic Codebook (ECB) mode of array
PLAN-TEXT. Result is array CIPHER-TEXT."
  (loop for i below (length cipher-text) do
    (setf (aref plain-text i) (decrypt o (aref cipher-text i))))
  plain-text)

;;; Mode: CBC - Cipher Block Chaining
(defgeneric block-encrypt-cbc (o plain-text cipher-text &key iv))
(defmethod block-encrypt-cbc (o plain-text cipher-text &key (iv 0))
  "AES encryption with Cipher Block Chaining (CBC) mode of array
PLAN-TEXT with initialization vector IV. Result is array
CIPHER-TEXT."
  (loop for i below (length plain-text)
	for kv = iv then ct
	for pt = (aref plain-text i)
	for ct = (encrypt o (logxor pt kv))
	do (setf (aref cipher-text i) ct))
  cipher-text)

(defgeneric block-decrypt-cbc (o cipher-text plain-text &key iv))
(defmethod block-decrypt-cbc (o cipher-text plain-text &key (iv 0))
  "AES decryption with Cipher Block Chaining (CBC) mode of array
CIPHER-TEXT with and initialization vector IV. Result is array
PLAN-TEXT."
  (loop for i below (length cipher-text)
	for kv = iv then ct
	for ct = (aref cipher-text i)
	for pt = (logxor (decrypt o ct) kv)
	do (setf (aref plain-text i) pt))
  plain-text)

;;; TODO
;;; Mode: CFB - Cipher Feed Back
;;; Mode: OFB - Output Feed Back
