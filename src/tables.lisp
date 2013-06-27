;;;; Creating tables
;;;; http://www.codeplanet.eu/tutorials/cpp/3-cpp/51-advanced-encryption-standard.html

(in-package #:aes)

;;; SBCL is quite strict about ANSI's definition of defconstant. ANSI says
;;; that doing defconstant of the same symbol more than once is undefined
;;; unless the new value is eql to the old value. Conforming to this
;;; specification is a nuisance when the "constant" value is only constant
;;; under some weaker test like string= or equal.
(defmacro define-constant (name value &optional doc)
  `(defconstant ,name (if (boundp ',name) (symbol-value ',name) ,value)
     ,@(when doc (list doc))))

(define-constant +sbox+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 8))))
      (loop for i below (length tbl)
	    for s = (ginverse i)
	    for x = s do
	      (loop repeat 4
		    do (setf s (dpb (ldb (byte 7 0) s) (byte 7 1) (ldb (byte 1 7) s)) ; rotate one bit to the left
			     x (logxor x s)))
	      (setf (aref tbl i) (logxor x #x63)))
      tbl)
  "Table of S-boxes.")

(define-constant +inv-sbox+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 8))))
      (loop for i below (length tbl)
	    for j = (aref +sbox+ i) do
	      (setf (aref tbl j) i))
      tbl)
  "Table of inverse S-boxes.")

(define-constant +encrypt0+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 32))))
      (loop for i below (length tbl)
	    for s = (aref +sbox+ i)
	    do (setf (aref tbl i) (dpb (g* 2 s) (byte 8 24) (dpb (g* 1 s) (byte 8 16) (dpb (g* 1 s) (byte 8 8) (g* 3 s))))))
      tbl)
  "encrypt0[x] = S[x].[02, 01, 01, 03]")

(define-constant +encrypt1+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 32))))
      (loop for i below (length tbl)
	    for e = (aref +encrypt0+ i)
	    do (setf (aref tbl i) (dpb (ldb (byte 8 0) e) (byte 8 24) (ldb (byte 24 8) e)))) ; rotate one byte to the right
      tbl)
  "encrypt1[x] = S[x].[03, 02, 01, 01]")

(define-constant +encrypt2+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 32))))
      (loop for i below (length tbl)
	    for e = (aref +encrypt1+ i)
	    do (setf (aref tbl i) (dpb (ldb (byte 8 0) e) (byte 8 24) (ldb (byte 24 8) e)))) ; rotate one byte to the right
      tbl)
  "encrypt2[x] = S[x].[01, 03, 02, 01]")

(define-constant +encrypt3+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 32))))
      (loop for i below (length tbl)
	    for e = (aref +encrypt2+ i)
	    do (setf (aref tbl i) (dpb (ldb (byte 8 0) e) (byte 8 24) (ldb (byte 24 8) e)))) ; rotate one byte to the right
      tbl)
  "encrypt3[x] = S[x].[01, 01, 03, 02]")

(define-constant +decrypt0+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 32))))
      (loop for i below (length tbl)
	    for s = (aref +inv-sbox+ i)
	    do (setf (aref tbl i) (dpb (g* 14 s) (byte 8 24) (dpb (g* 9 s) (byte 8 16) (dpb (g* 13 s) (byte 8 8) (g* 11 s))))))
      tbl)
  "decrypt0[x] = S'[x].[0e, 09, 0d, 0b]")

(define-constant +decrypt1+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 32))))
      (loop for i below (length tbl)
	    for d = (aref +decrypt0+ i)
	    do (setf (aref tbl i) (dpb (ldb (byte 8 0) d) (byte 8 24) (ldb (byte 24 8) d)))) ; rotate one byte to the right
      tbl)
  "decrypt1[x] = S'[x].[0b, 0e, 09, 0d]")

(define-constant +decrypt2+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 32))))
      (loop for i below (length tbl)
	    for d = (aref +decrypt1+ i)
	    do (setf (aref tbl i) (dpb (ldb (byte 8 0) d) (byte 8 24) (ldb (byte 24 8) d)))) ; rotate one byte to the right
      tbl)
  "decrypt2[x] = S'[x].[0d, 0b, 0e, 09]")

(define-constant +decrypt3+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 32))))
      (loop for i below (length tbl)
	    for d = (aref +decrypt2+ i)
	    do (setf (aref tbl i) (dpb (ldb (byte 8 0) d) (byte 8 24) (ldb (byte 24 8) d)))) ; rotate one byte to the right
      tbl)
  "decrypt3[x] = S'[x].[09, 0d, 0b, 0e]")

(define-constant +round-const+
    (let ((tbl (make-array 10 :element-type '(unsigned-byte 32) :initial-element 0)))
      (loop for i below (length tbl)
	    for x = 1 then (xtime x) do
	      (setf (aref tbl i) (dpb x (byte 8 24) 0)))
      tbl)
  "10 round constants for key expansion.")
