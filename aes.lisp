;;;; AES implemention

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
    (make-array 256 :element-type '(unsigned-byte 8) :initial-contents
		'(#x63 #x7c #x77 #x7b #xf2 #x6b #x6f #xc5 #x30 #x01 #x67 #x2b #xfe #xd7 #xab #x76
		  #xca #x82 #xc9 #x7d #xfa #x59 #x47 #xf0 #xad #xd4 #xa2 #xaf #x9c #xa4 #x72 #xc0
		  #xb7 #xfd #x93 #x26 #x36 #x3f #xf7 #xcc #x34 #xa5 #xe5 #xf1 #x71 #xd8 #x31 #x15
		  #x04 #xc7 #x23 #xc3 #x18 #x96 #x05 #x9a #x07 #x12 #x80 #xe2 #xeb #x27 #xb2 #x75
		  #x09 #x83 #x2c #x1a #x1b #x6e #x5a #xa0 #x52 #x3b #xd6 #xb3 #x29 #xe3 #x2f #x84
		  #x53 #xd1 #x00 #xed #x20 #xfc #xb1 #x5b #x6a #xcb #xbe #x39 #x4a #x4c #x58 #xcf
		  #xd0 #xef #xaa #xfb #x43 #x4d #x33 #x85 #x45 #xf9 #x02 #x7f #x50 #x3c #x9f #xa8
		  #x51 #xa3 #x40 #x8f #x92 #x9d #x38 #xf5 #xbc #xb6 #xda #x21 #x10 #xff #xf3 #xd2
		  #xcd #x0c #x13 #xec #x5f #x97 #x44 #x17 #xc4 #xa7 #x7e #x3d #x64 #x5d #x19 #x73
		  #x60 #x81 #x4f #xdc #x22 #x2a #x90 #x88 #x46 #xee #xb8 #x14 #xde #x5e #x0b #xdb
		  #xe0 #x32 #x3a #x0a #x49 #x06 #x24 #x5c #xc2 #xd3 #xac #x62 #x91 #x95 #xe4 #x79
		  #xe7 #xc8 #x37 #x6d #x8d #xd5 #x4e #xa9 #x6c #x56 #xf4 #xea #x65 #x7a #xae #x08
		  #xba #x78 #x25 #x2e #x1c #xa6 #xb4 #xc6 #xe8 #xdd #x74 #x1f #x4b #xbd #x8b #x8a
		  #x70 #x3e #xb5 #x66 #x48 #x03 #xf6 #x0e #x61 #x35 #x57 #xb9 #x86 #xc1 #x1d #x9e
		  #xe1 #xf8 #x98 #x11 #x69 #xd9 #x8e #x94 #x9b #x1e #x87 #xe9 #xce #x55 #x28 #xdf
		  #x8c #xa1 #x89 #x0d #xbf #xe6 #x42 #x68 #x41 #x99 #x2d #x0f #xb0 #x54 #xbb #x16)))

(define-constant +inv-sbox+
    (make-array 256 :element-type '(unsigned-byte 8) :initial-contents
		'(#x52 #x09 #x6a #xd5 #x30 #x36 #xa5 #x38 #xbf #x40 #xa3 #x9e #x81 #xf3 #xd7 #xfb
		  #x7c #xe3 #x39 #x82 #x9b #x2f #xff #x87 #x34 #x8e #x43 #x44 #xc4 #xde #xe9 #xcb
		  #x54 #x7b #x94 #x32 #xa6 #xc2 #x23 #x3d #xee #x4c #x95 #x0b #x42 #xfa #xc3 #x4e
		  #x08 #x2e #xa1 #x66 #x28 #xd9 #x24 #xb2 #x76 #x5b #xa2 #x49 #x6d #x8b #xd1 #x25
		  #x72 #xf8 #xf6 #x64 #x86 #x68 #x98 #x16 #xd4 #xa4 #x5c #xcc #x5d #x65 #xb6 #x92
		  #x6c #x70 #x48 #x50 #xfd #xed #xb9 #xda #x5e #x15 #x46 #x57 #xa7 #x8d #x9d #x84
		  #x90 #xd8 #xab #x00 #x8c #xbc #xd3 #x0a #xf7 #xe4 #x58 #x05 #xb8 #xb3 #x45 #x06
		  #xd0 #x2c #x1e #x8f #xca #x3f #x0f #x02 #xc1 #xaf #xbd #x03 #x01 #x13 #x8a #x6b
		  #x3a #x91 #x11 #x41 #x4f #x67 #xdc #xea #x97 #xf2 #xcf #xce #xf0 #xb4 #xe6 #x73
		  #x96 #xac #x74 #x22 #xe7 #xad #x35 #x85 #xe2 #xf9 #x37 #xe8 #x1c #x75 #xdf #x6e
		  #x47 #xf1 #x1a #x71 #x1d #x29 #xc5 #x89 #x6f #xb7 #x62 #x0e #xaa #x18 #xbe #x1b
		  #xfc #x56 #x3e #x4b #xc6 #xd2 #x79 #x20 #x9a #xdb #xc0 #xfe #x78 #xcd #x5a #xf4
		  #x1f #xdd #xa8 #x33 #x88 #x07 #xc7 #x31 #xb1 #x12 #x10 #x59 #x27 #x80 #xec #x5f
		  #x60 #x51 #x7f #xa9 #x19 #xb5 #x4a #x0d #x2d #xe5 #x7a #x9f #x93 #xc9 #x9c #xef
		  #xa0 #xe0 #x3b #x4d #xae #x2a #xf5 #xb0 #xc8 #xeb #xbb #x3c #x83 #x53 #x99 #x61
		  #x17 #x2b #x04 #x7e #xba #x77 #xd6 #x26 #xe1 #x69 #x14 #x63 #x55 #x21 #x0c #x7d)))

(define-constant +round-const+
    (make-array 10 :element-type '(unsigned-byte 32) :initial-contents
		'(#x01000000 #x02000000 #x04000000 #x08000000
		  #x10000000 #x20000000 #x40000000 #x80000000
		  #x1b000000 #x36000000)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Key Expansion
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun sub-word (n)
  (declare (type (unsigned-byte 32) n))
  (let ((result 0))
    (declare (type (unsigned-byte 32) result))
    (loop for i below 32 by 8
	  for b = (aref +sbox+ (ldb (byte 8 i) n))
	  do (setf result (dpb b (byte 8 i) result)))
    result))

(defun rot-word (n)
  (declare (type (unsigned-byte 32) n))
  (let ((result 0))
    (declare (type (unsigned-byte 32) result))
    (setf result (dpb (ldb (byte 24 0) n) (byte 24 8) result))
    (setf result (dpb (ldb (byte 8 24) n) (byte  8 0) result))
    result))

(defun round-const (i nk)
  (aref +round-const+ (1- (truncate i nk))))

(defun key-expansion (cipher-key nk)
  (let ((w (make-array (* 4 (+ nk 7)) :element-type '(unsigned-byte 32)))
	(k (make-array      (+ nk 7)  :element-type '(unsigned-byte 128))))
    ;; first Nk keys
    (loop for i below nk do
	 (setf (aref w i) (ldb (byte 32 (* 32 (- nk i 1))) cipher-key)))

    ;; rest of keys
    (loop for i from nk below (length w)
       for temp = (aref w (1- i)) do
	 (cond
	   ((= 0 (rem i nk)) (setf temp (logxor (sub-word (rot-word temp)) (round-const i nk))))
	   ((and (> nk 6) (= 4 (rem i nk))) (setf temp (sub-word temp))))
	 (setf (aref w i) (logxor (aref w (- i nk)) temp)))

    ;; copy w to k
    (loop for i below (length k) do
	 (loop for j below 4 do
	      (setf (aref k i) (dpb (aref w (+ (* i 4) j)) (byte 32 (* 32 (- 3 j))) (aref k i)))))
    k))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Cipher
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(declaim (inline add-round-key))
(defun add-round-key (state key)
  (declare (type (unsigned-byte 128) state key))
  (logxor state key))

(defun sub-bytes (n &optional (sbox +sbox+))
  (declare (type (unsigned-byte 128) n)
	   (type (array (unsigned-byte 8) (256)) sbox))
  (let ((result 0))
    (declare (type (unsigned-byte 128) result))
    (loop for i below 128 by 8
	  for b = (aref sbox (ldb (byte 8 i) n))
	  do (setf result (dpb b (byte 8 i) result)))
    result))

(defun inv-sub-bytes (n)
  (sub-bytes n +inv-sbox+))

(defun shift-rows (n)
  (declare (type (unsigned-byte 128) n))
  (let ((result 0))
    (declare (type (unsigned-byte 128) result))
    (loop for i below 128 by 8
          for j = (mod (+ (* 5 i) 32) 128)
	  do (setf result (dpb (ldb (byte 8 j) n) (byte 8 i) result)))
    result))

(defun inv-shift-rows (n)
  (declare (type (unsigned-byte 128) n))
  (let ((result 0))
    (declare (type (unsigned-byte 128) result))
    (loop for i below 128 by 8
          for j = (mod (+ (* -3 i) 96) 128)
	  do (setf result (dpb (ldb (byte 8 j) n) (byte 8 i) result)))
    result))

(declaim (inline xtime))
(defun xtime (n)
  "Galois multiplication, return 2n."
  (declare (type (unsigned-byte 8) n))
  (let ((m (ash n 1)))
    (if (logtest m #x100)
	(logxor m #x11b)
	m)))

(defun g* (n1 n2)
  "Galois multiplication, return n1*n2."
  (declare (type (unsigned-byte 8) n1 n2)
	   (optimize speed))
  (let ((p 0))
    (declare (type (unsigned-byte 8) p))
    (loop repeat 8 do
      (if (logtest n2 1)
	  (setf p (logxor p n1)))
      (setf n1 (xtime n1)
	    n2 (ash n2 -1)))
    p))

(defun mix-columns (n)
  (declare (type (unsigned-byte 128) n))
  (let* ((n0  (ldb (byte 8   0) n))
	 (n1  (ldb (byte 8   8) n))
	 (n2  (ldb (byte 8  16) n))
	 (n3  (ldb (byte 8  24) n))
	 (n4  (ldb (byte 8  32) n))
	 (n5  (ldb (byte 8  40) n))
	 (n6  (ldb (byte 8  48) n))
	 (n7  (ldb (byte 8  56) n))
	 (n8  (ldb (byte 8  64) n))
	 (n9  (ldb (byte 8  72) n))
	 (n10 (ldb (byte 8  80) n))
	 (n11 (ldb (byte 8  88) n))
	 (n12 (ldb (byte 8  96) n))
	 (n13 (ldb (byte 8 104) n))
	 (n14 (ldb (byte 8 112) n))
	 (n15 (ldb (byte 8 120) n))

	 (b00 (logxor (g* 2 n15) (g* 3 n14) (g* 1 n13) (g* 1 n12)))
	 (b10 (logxor (g* 1 n15) (g* 2 n14) (g* 3 n13) (g* 1 n12)))
	 (b20 (logxor (g* 1 n15) (g* 1 n14) (g* 2 n13) (g* 3 n12)))
	 (b30 (logxor (g* 3 n15) (g* 1 n14) (g* 1 n13) (g* 2 n12)))

	 (b01 (logxor (g* 2 n11) (g* 3 n10) (g* 1 n9) (g* 1 n8)))
	 (b11 (logxor (g* 1 n11) (g* 2 n10) (g* 3 n9) (g* 1 n8)))
	 (b21 (logxor (g* 1 n11) (g* 1 n10) (g* 2 n9) (g* 3 n8)))
	 (b31 (logxor (g* 3 n11) (g* 1 n10) (g* 1 n9) (g* 2 n8)))

	 (b02 (logxor (g* 2 n7) (g* 3 n6) (g* 1 n5) (g* 1 n4)))
	 (b12 (logxor (g* 1 n7) (g* 2 n6) (g* 3 n5) (g* 1 n4)))
	 (b22 (logxor (g* 1 n7) (g* 1 n6) (g* 2 n5) (g* 3 n4)))
	 (b32 (logxor (g* 3 n7) (g* 1 n6) (g* 1 n5) (g* 2 n4)))

	 (b03 (logxor (g* 2 n3) (g* 3 n2) (g* 1 n1) (g* 1 n0)))
	 (b13 (logxor (g* 1 n3) (g* 2 n2) (g* 3 n1) (g* 1 n0)))
	 (b23 (logxor (g* 1 n3) (g* 1 n2) (g* 2 n1) (g* 3 n0)))
	 (b33 (logxor (g* 3 n3) (g* 1 n2) (g* 1 n1) (g* 2 n0)))

	 (b 0))
    (declare (type (unsigned-byte 8) n0 n1 n2 n8 n4 n5 n6 n7 n8 n9 n10 n11 n12 n13 n14 n15)
	     (type (unsigned-byte 8) b00 b01 b02 b03 b10 b11 b12 b13 b20 b21 b22 b23 b30 b31 b32 b33)
	     (type (unsigned-byte 128) b))
    (setf b (dpb b00 (byte 8 120) b) b (dpb b01 (byte 8 88) b) b (dpb b02 (byte 8 56) b) b (dpb b03 (byte 8 24) b)
	  b (dpb b10 (byte 8 112) b) b (dpb b11 (byte 8 80) b) b (dpb b12 (byte 8 48) b) b (dpb b13 (byte 8 16) b)
	  b (dpb b20 (byte 8 104) b) b (dpb b21 (byte 8 72) b) b (dpb b22 (byte 8 40) b) b (dpb b23 (byte 8  8) b)
	  b (dpb b30 (byte 8  96) b) b (dpb b31 (byte 8 64) b) b (dpb b32 (byte 8 32) b) b (dpb b33 (byte 8  0) b))))

(defun inv-mix-columns (n)
  (declare (type (unsigned-byte 128) n))
  (let* ((n0  (ldb (byte 8   0) n))
	 (n1  (ldb (byte 8   8) n))
	 (n2  (ldb (byte 8  16) n))
	 (n3  (ldb (byte 8  24) n))
	 (n4  (ldb (byte 8  32) n))
	 (n5  (ldb (byte 8  40) n))
	 (n6  (ldb (byte 8  48) n))
	 (n7  (ldb (byte 8  56) n))
	 (n8  (ldb (byte 8  64) n))
	 (n9  (ldb (byte 8  72) n))
	 (n10 (ldb (byte 8  80) n))
	 (n11 (ldb (byte 8  88) n))
	 (n12 (ldb (byte 8  96) n))
	 (n13 (ldb (byte 8 104) n))
	 (n14 (ldb (byte 8 112) n))
	 (n15 (ldb (byte 8 120) n))

	 (b00 (logxor (g* 14 n15) (g* 11 n14) (g* 13 n13) (g*  9 n12)))
	 (b10 (logxor (g*  9 n15) (g* 14 n14) (g* 11 n13) (g* 13 n12)))
	 (b20 (logxor (g* 13 n15) (g*  9 n14) (g* 14 n13) (g* 11 n12)))
	 (b30 (logxor (g* 11 n15) (g* 13 n14) (g*  9 n13) (g* 14 n12)))

	 (b01 (logxor (g* 14 n11) (g* 11 n10) (g* 13 n9) (g*  9 n8)))
	 (b11 (logxor (g*  9 n11) (g* 14 n10) (g* 11 n9) (g* 13 n8)))
	 (b21 (logxor (g* 13 n11) (g*  9 n10) (g* 14 n9) (g* 11 n8)))
	 (b31 (logxor (g* 11 n11) (g* 13 n10) (g*  9 n9) (g* 14 n8)))

	 (b02 (logxor (g* 14 n7) (g* 11 n6) (g* 13 n5) (g*  9 n4)))
	 (b12 (logxor (g*  9 n7) (g* 14 n6) (g* 11 n5) (g* 13 n4)))
	 (b22 (logxor (g* 13 n7) (g*  9 n6) (g* 14 n5) (g* 11 n4)))
	 (b32 (logxor (g* 11 n7) (g* 13 n6) (g*  9 n5) (g* 14 n4)))

	 (b03 (logxor (g* 14 n3) (g* 11 n2) (g* 13 n1) (g*  9 n0)))
	 (b13 (logxor (g*  9 n3) (g* 14 n2) (g* 11 n1) (g* 13 n0)))
	 (b23 (logxor (g* 13 n3) (g*  9 n2) (g* 14 n1) (g* 11 n0)))
	 (b33 (logxor (g* 11 n3) (g* 13 n2) (g*  9 n1) (g* 14 n0)))

	 (b 0))
    (declare (type (unsigned-byte 8) n0 n1 n2 n8 n4 n5 n6 n7 n8 n9 n10 n11 n12 n13 n14 n15)
	     (type (unsigned-byte 8) b00 b01 b02 b03 b10 b11 b12 b13 b20 b21 b22 b23 b30 b31 b32 b33)
	     (type (unsigned-byte 128) b))
    (setf b (dpb b00 (byte 8 120) b) b (dpb b01 (byte 8 88) b) b (dpb b02 (byte 8 56) b) b (dpb b03 (byte 8 24) b)
	  b (dpb b10 (byte 8 112) b) b (dpb b11 (byte 8 80) b) b (dpb b12 (byte 8 48) b) b (dpb b13 (byte 8 16) b)
	  b (dpb b20 (byte 8 104) b) b (dpb b21 (byte 8 72) b) b (dpb b22 (byte 8 40) b) b (dpb b23 (byte 8  8) b)
	  b (dpb b30 (byte 8  96) b) b (dpb b31 (byte 8 64) b) b (dpb b32 (byte 8 32) b) b (dpb b33 (byte 8  0) b))))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Class definitions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defclass aes ()
  ((cipher-key    :type (unsigned-byte 128) :initarg :cipher-key )
   (expanded-keys :type (simple-array (unsigned-byte 128)))
   (state         :type (unsigned-byte 128))))

(defclass aes-128 (aes) ())
(defclass aes-192 (aes) ())
(defclass aes-256 (aes) ())

(defmethod initialize-instance :after ((o aes-128) &rest initargs)
  (declare (ignore initargs))
  (with-slots (expanded-keys cipher-key) o
    (setf expanded-keys (key-expansion cipher-key 4))))

(defmethod initialize-instance :after ((o aes-192) &rest initargs)
  (declare (ignore initargs))
  (with-slots (expanded-keys cipher-key) o
    (setf expanded-keys (key-expansion cipher-key 6))))

(defmethod initialize-instance :after ((o aes-256) &rest initargs)
  (declare (ignore initargs))
  (with-slots (expanded-keys cipher-key) o
    (setf expanded-keys (key-expansion cipher-key 8))))

(defgeneric encode (o n));
(defmethod encode ((o aes) n)
  (with-slots (expanded-keys state) o
    (setf state (add-round-key n (aref expanded-keys 0)))
    (loop for i from 1 below (1- (length expanded-keys)) do
      (setf state (sub-bytes state))
      (setf state (shift-rows state))
      (setf state (mix-columns state))
      (setf state (add-round-key state (aref expanded-keys i))))
    (setf state (sub-bytes state))
    (setf state (shift-rows state))
    (add-round-key state (aref expanded-keys (1- (length expanded-keys))))))

(defgeneric decode (o n));
(defmethod decode ((o aes) n)
  (with-slots (expanded-keys state) o
    (setf state (add-round-key n (aref expanded-keys (1- (length expanded-keys)))))
    (loop for i from (- (length expanded-keys) 2) downto 1 do
      (setf state (inv-shift-rows state))
      (setf state (inv-sub-bytes state))
      (setf state (add-round-key state (aref expanded-keys i)))
      (setf state (inv-mix-columns state)))
    (setf state (inv-shift-rows state))
    (setf state (inv-sub-bytes state))
    (add-round-key state (aref expanded-keys 0))))
