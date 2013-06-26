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

(define-constant +exp-table+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 8))))
      (loop for i below (length tbl)
	    for a = 1 then (g* a 3) do
	      (setf (aref tbl i) a))
      tbl)
  "Table of exponentials with base 3.")

(define-constant +log-table+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 8))))
      (loop for i below (length tbl)
	    for j = (aref +exp-table+ i) do
	      (setf (aref tbl j) i))
      tbl)
  "Table of logarithms with base 3.")

(define-constant +sbox+
    (labels ((ginverse (n)
	       "Calculates the Galois multiplicative inverse of N."
	       (declare (type (unsigned-byte 8) n))
	       (if (= n 0)
		   0
		   (aref +exp-table+ (- (aref +log-table+ 1) (aref +log-table+ n))))))

      (let ((tbl (make-array 256 :element-type '(unsigned-byte 8))))
	(loop for i below (length tbl)
	      for s = (ginverse i)
	      for x = s do
		(loop repeat 4 do
		  (setf s (dpb (ldb (byte 7 0) s) (byte 7 1) (ldb (byte 1 7) s)) ; rotate one bit to the left
			x (logxor x s)))
		(setf (aref tbl i) (logxor x #x63)))
	tbl))
  "Table of S-boxes.")

(define-constant +inv-sbox+
    (let ((tbl (make-array 256 :element-type '(unsigned-byte 8))))
      (loop for i below (length tbl)
	    for j = (aref +sbox+ i) do
	      (setf (aref tbl j) i))
      tbl)
  "Table of inverse S-boxes.")

(define-constant +round-const+
    (let ((tbl (make-array 10 :element-type '(unsigned-byte 32) :initial-element 0)))
      (loop for i below (length tbl)
	    for x = 1 then (xtime x) do
	      (setf (aref tbl i) (dpb x (byte 8 24) 0)))
      tbl)
  "Ten round constants for key expansion.")
