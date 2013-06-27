;;;; AES implemention

(in-package #:aes)

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
  (dpb (ldb (byte 24 0) n) (byte 24 8) (ldb (byte 8 24) n)))

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

(defun decryption-key-expansion (ek)
  (let* ((length (length ek))
	 (dk (make-array length :element-type '(unsigned-byte 128) :initial-contents ek)))
    (loop for i from 1 below (1- length) do
      (setf (aref dk i) (inv-mix-columns (aref ek i))))
    dk))

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

(defun mix-columns-sub-bytes (n)
  "Perform sub-bytes and mix-columns in one step."
  (declare (type (unsigned-byte 128) n))
  (let* ((e0  (aref +encrypt0+ (ldb (byte 8 120) n))) ; (2*s0   1*s0   1*s0   3*s0)
	 (e1  (aref +encrypt1+ (ldb (byte 8 112) n))) ; (3*s1   2*s1   1*s1   1*s1)
	 (e2  (aref +encrypt2+ (ldb (byte 8 104) n))) ; (1*s2   3*s2   2*s2   1*s2)
	 (e3  (aref +encrypt3+ (ldb (byte 8  96) n))) ; (1*s3   1*s3   3*s3   2*s3)

	 (e4  (aref +encrypt0+ (ldb (byte 8  88) n))) ; (2*s4   1*s4   1*s4   3*s4)
	 (e5  (aref +encrypt1+ (ldb (byte 8  80) n))) ; (3*s5   2*s5   1*s5   1*s5)
	 (e6  (aref +encrypt2+ (ldb (byte 8  72) n))) ; (1*s6   3*s6   2*s6   1*s6)
	 (e7  (aref +encrypt3+ (ldb (byte 8  64) n))) ; (1*s7   1*s7   3*s7   2*s7)

	 (e8  (aref +encrypt0+ (ldb (byte 8  56) n))) ; (2*s8   1*s8   1*s8   3*s8)
	 (e9  (aref +encrypt1+ (ldb (byte 8  48) n))) ; (3*s9   2*s9   1*s9   1*s9)
	 (e10 (aref +encrypt2+ (ldb (byte 8  40) n))) ; (1*s10  3*s10  2*s10  1*s10)
	 (e11 (aref +encrypt3+ (ldb (byte 8  32) n))) ; (1*s11  1*s11  3*s11  2*s11)

	 (e12 (aref +encrypt0+ (ldb (byte 8  24) n))) ; (2*s12  1*s12  1*s12  3*s12)
	 (e13 (aref +encrypt1+ (ldb (byte 8  16) n))) ; (3*s13  2*s13  1*s13  1*s13)
	 (e14 (aref +encrypt2+ (ldb (byte 8   8) n))) ; (1*s14  3*s14  2*s14  1*s14)
	 (e15 (aref +encrypt3+ (ldb (byte 8   0) n))) ; (1*s15  1*s15  3*s15  2*s15)

	 (b00 (logxor (ldb (byte 8 24)  e0) (ldb (byte 8 24)  e1) (ldb (byte 8 24)  e2) (ldb (byte 8 24)  e3)))
	 (b10 (logxor (ldb (byte 8 16)  e0) (ldb (byte 8 16)  e1) (ldb (byte 8 16)  e2) (ldb (byte 8 16)  e3)))
	 (b20 (logxor (ldb (byte 8  8)  e0) (ldb (byte 8  8)  e1) (ldb (byte 8  8)  e2) (ldb (byte 8  8)  e3)))
	 (b30 (logxor (ldb (byte 8  0)  e0) (ldb (byte 8  0)  e1) (ldb (byte 8  0)  e2) (ldb (byte 8  0)  e3)))

	 (b01 (logxor (ldb (byte 8 24)  e4) (ldb (byte 8 24)  e5) (ldb (byte 8 24)  e6) (ldb (byte 8 24)  e7)))
	 (b11 (logxor (ldb (byte 8 16)  e4) (ldb (byte 8 16)  e5) (ldb (byte 8 16)  e6) (ldb (byte 8 16)  e7)))
	 (b21 (logxor (ldb (byte 8  8)  e4) (ldb (byte 8  8)  e5) (ldb (byte 8  8)  e6) (ldb (byte 8  8)  e7)))
	 (b31 (logxor (ldb (byte 8  0)  e4) (ldb (byte 8  0)  e5) (ldb (byte 8  0)  e6) (ldb (byte 8  0)  e7)))

	 (b02 (logxor (ldb (byte 8 24)  e8) (ldb (byte 8 24)  e9) (ldb (byte 8 24) e10) (ldb (byte 8 24) e11)))
	 (b12 (logxor (ldb (byte 8 16)  e8) (ldb (byte 8 16)  e9) (ldb (byte 8 16) e10) (ldb (byte 8 16) e11)))
	 (b22 (logxor (ldb (byte 8  8)  e8) (ldb (byte 8  8)  e9) (ldb (byte 8  8) e10) (ldb (byte 8  8) e11)))
	 (b32 (logxor (ldb (byte 8  0)  e8) (ldb (byte 8  0)  e9) (ldb (byte 8  0) e10) (ldb (byte 8  0) e11)))

	 (b03 (logxor (ldb (byte 8 24) e12) (ldb (byte 8 24) e13) (ldb (byte 8 24) e14) (ldb (byte 8 24) e15)))
	 (b13 (logxor (ldb (byte 8 16) e12) (ldb (byte 8 16) e13) (ldb (byte 8 16) e14) (ldb (byte 8 16) e15)))
	 (b23 (logxor (ldb (byte 8  8) e12) (ldb (byte 8  8) e13) (ldb (byte 8  8) e14) (ldb (byte 8  8) e15)))
	 (b33 (logxor (ldb (byte 8  0) e12) (ldb (byte 8  0) e13) (ldb (byte 8  0) e14) (ldb (byte 8  0) e15))))
    (declare (type (unsigned-byte 32) e0 e1 e2 e8 e4 e5 e6 e7 e8 e9 e10 e11 e12 e13 e14 e15)
	     (type (unsigned-byte 8) b00 b01 b02 b03 b10 b11 b12 b13 b20 b21 b22 b23 b30 b31 b32 b33))
    (dpb
     (dpb (dpb (dpb b00 (byte 8 8) b10) (byte 16 16) (dpb b20 (byte 8 8) b30))
	  (byte 32 32)
	  (dpb (dpb b01 (byte 8 8) b11) (byte 16 16) (dpb b21 (byte 8 8) b31)))
     (byte 64 64)
     (dpb (dpb (dpb b02 (byte 8 8) b12) (byte 16 16) (dpb b22 (byte 8 8) b32))
	  (byte 32 32)
	  (dpb (dpb b03 (byte 8 8) b13) (byte 16 16) (dpb b23 (byte 8 8) b33))))))

(defun inv-mix-columns-sub-bytes (n)
  "Perform inv-sub-bytes and inv-mix-columns in one step."
  (declare (type (unsigned-byte 128) n))
  (let* ((d0  (aref +decrypt0+ (ldb (byte 8 120) n))) ; (14*s0   1*s0   13*s0    9*s0)
	 (d1  (aref +decrypt1+ (ldb (byte 8 112) n))) ; ( 9*s1   14*s1   1*s1   13*s1)
	 (d2  (aref +decrypt2+ (ldb (byte 8 104) n))) ; (13*s2    9*s2   14*s2   1*s2)
	 (d3  (aref +decrypt3+ (ldb (byte 8  96) n))) ; (11*s3   13*s3    9*s3   14*s3)

	 (d4  (aref +decrypt0+ (ldb (byte 8  88) n))) ; (14*s4   11*s4   13*s4    9*s4)
	 (d5  (aref +decrypt1+ (ldb (byte 8  80) n))) ; ( 9*s5   14*s5   11*s5   13*s5)
	 (d6  (aref +decrypt2+ (ldb (byte 8  72) n))) ; (13*s6    9*s6   14*s6   11*s6)
	 (d7  (aref +decrypt3+ (ldb (byte 8  64) n))) ; (11*s7   13*s7    9*s7   14*s7)

	 (d8  (aref +decrypt0+ (ldb (byte 8  56) n))) ; (14*s8   11*s8   13*s8    9*s8)
	 (d9  (aref +decrypt1+ (ldb (byte 8  48) n))) ; ( 9*s9   14*s9   11*s9   13*s9)
	 (d10 (aref +decrypt2+ (ldb (byte 8  40) n))) ; (13*s10   9*s10  14*s10  11*s10)
	 (d11 (aref +decrypt3+ (ldb (byte 8  32) n))) ; (11*s11  13*s11   9*s11  14*s11)

	 (d12 (aref +decrypt0+ (ldb (byte 8  24) n))) ; (14*s12  11*s12  13*s12   9*s12)
	 (d13 (aref +decrypt1+ (ldb (byte 8  16) n))) ; ( 9*s13  14*s13  11*s13  13*s13)
	 (d14 (aref +decrypt2+ (ldb (byte 8   8) n))) ; (13*s14   9*s14  14*s14  11*s14)
	 (d15 (aref +decrypt3+ (ldb (byte 8   0) n))) ; (11*s15  13*s15   9*s15  14*s15)

	 (b00 (logxor (ldb (byte 8 24)  d0) (ldb (byte 8 24)  d1) (ldb (byte 8 24)  d2) (ldb (byte 8 24)  d3)))
	 (b10 (logxor (ldb (byte 8 16)  d0) (ldb (byte 8 16)  d1) (ldb (byte 8 16)  d2) (ldb (byte 8 16)  d3)))
	 (b20 (logxor (ldb (byte 8  8)  d0) (ldb (byte 8  8)  d1) (ldb (byte 8  8)  d2) (ldb (byte 8  8)  d3)))
	 (b30 (logxor (ldb (byte 8  0)  d0) (ldb (byte 8  0)  d1) (ldb (byte 8  0)  d2) (ldb (byte 8  0)  d3)))

	 (b01 (logxor (ldb (byte 8 24)  d4) (ldb (byte 8 24)  d5) (ldb (byte 8 24)  d6) (ldb (byte 8 24)  d7)))
	 (b11 (logxor (ldb (byte 8 16)  d4) (ldb (byte 8 16)  d5) (ldb (byte 8 16)  d6) (ldb (byte 8 16)  d7)))
	 (b21 (logxor (ldb (byte 8  8)  d4) (ldb (byte 8  8)  d5) (ldb (byte 8  8)  d6) (ldb (byte 8  8)  d7)))
	 (b31 (logxor (ldb (byte 8  0)  d4) (ldb (byte 8  0)  d5) (ldb (byte 8  0)  d6) (ldb (byte 8  0)  d7)))

	 (b02 (logxor (ldb (byte 8 24)  d8) (ldb (byte 8 24)  d9) (ldb (byte 8 24) d10) (ldb (byte 8 24) d11)))
	 (b12 (logxor (ldb (byte 8 16)  d8) (ldb (byte 8 16)  d9) (ldb (byte 8 16) d10) (ldb (byte 8 16) d11)))
	 (b22 (logxor (ldb (byte 8  8)  d8) (ldb (byte 8  8)  d9) (ldb (byte 8  8) d10) (ldb (byte 8  8) d11)))
	 (b32 (logxor (ldb (byte 8  0)  d8) (ldb (byte 8  0)  d9) (ldb (byte 8  0) d10) (ldb (byte 8  0) d11)))

	 (b03 (logxor (ldb (byte 8 24) d12) (ldb (byte 8 24) d13) (ldb (byte 8 24) d14) (ldb (byte 8 24) d15)))
	 (b13 (logxor (ldb (byte 8 16) d12) (ldb (byte 8 16) d13) (ldb (byte 8 16) d14) (ldb (byte 8 16) d15)))
	 (b23 (logxor (ldb (byte 8  8) d12) (ldb (byte 8  8) d13) (ldb (byte 8  8) d14) (ldb (byte 8  8) d15)))
	 (b33 (logxor (ldb (byte 8  0) d12) (ldb (byte 8  0) d13) (ldb (byte 8  0) d14) (ldb (byte 8  0) d15))))
    (declare (type (unsigned-byte 32) d0 d1 d2 d8 d4 d5 d6 d7 d8 d9 d10 d11 d12 d13 d14 d15)
	     (type (unsigned-byte 8) b00 b01 b02 b03 b10 b11 b12 b13 b20 b21 b22 b23 b30 b31 b32 b33))
    (dpb
     (dpb (dpb (dpb b00 (byte 8 8) b10) (byte 16 16) (dpb b20 (byte 8 8) b30))
	  (byte 32 32)
	  (dpb (dpb b01 (byte 8 8) b11) (byte 16 16) (dpb b21 (byte 8 8) b31)))
     (byte 64 64)
     (dpb (dpb (dpb b02 (byte 8 8) b12) (byte 16 16) (dpb b22 (byte 8 8) b32))
	  (byte 32 32)
	  (dpb (dpb b03 (byte 8 8) b13) (byte 16 16) (dpb b23 (byte 8 8) b33))))))

(defun inv-mix-columns (n)
  (declare (type (unsigned-byte 128) n))
  (inv-mix-columns-sub-bytes (sub-bytes n)))

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; Class definitions
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defclass aes ()
  ((expanded-encryption-keys :type (simple-array (unsigned-byte 128)))
   (expanded-decryption-keys :type (simple-array (unsigned-byte 128)))))

(defclass aes-128 (aes)
  ((cipher-key :type (unsigned-byte 128) :initarg :cipher-key)))

(defclass aes-192 (aes)
  ((cipher-key :type (unsigned-byte 192) :initarg :cipher-key)))

(defclass aes-256 (aes)
  ((cipher-key :type (unsigned-byte 256) :initarg :cipher-key)))

(defmethod initialize-instance :after ((o aes-128) &rest initargs)
  (declare (ignore initargs))
  (with-slots (cipher-key expanded-encryption-keys expanded-decryption-keys) o
    (setf expanded-encryption-keys (key-expansion cipher-key 4)
	  expanded-decryption-keys (decryption-key-expansion expanded-encryption-keys))))

(defmethod initialize-instance :after ((o aes-192) &rest initargs)
  (declare (ignore initargs))
  (with-slots (cipher-key expanded-encryption-keys expanded-decryption-keys) o
    (setf expanded-encryption-keys (key-expansion cipher-key 6)
	  expanded-decryption-keys (decryption-key-expansion expanded-encryption-keys))))

(defmethod initialize-instance :after ((o aes-256) &rest initargs)
  (declare (ignore initargs))
  (with-slots (cipher-key expanded-encryption-keys expanded-decryption-keys) o
    (setf expanded-encryption-keys (key-expansion cipher-key 8)
	  expanded-decryption-keys (decryption-key-expansion expanded-encryption-keys))))

(defgeneric encrypt (o n))
(defmethod encrypt ((o aes) n)
  (with-slots (expanded-encryption-keys state) o
    (let ((state (add-round-key n (aref expanded-encryption-keys 0))))
      (declare (type (unsigned-byte 128) state))
      (loop for i from 1 below (1- (length expanded-encryption-keys)) do
	(setf state (shift-rows state)
	      state (mix-columns-sub-bytes state)
	      state (add-round-key state (aref expanded-encryption-keys i))))
      (setf state (sub-bytes state)
	    state (shift-rows state))
      (add-round-key state (aref expanded-encryption-keys (1- (length expanded-encryption-keys)))))))

(defgeneric decrypt (o n))
(defmethod decrypt ((o aes) n)
  (with-slots (expanded-decryption-keys state) o
    (let ((state (add-round-key n (aref expanded-decryption-keys (1- (length expanded-decryption-keys))))))
      (declare (type (unsigned-byte 128) state))
      (loop for i from (- (length expanded-decryption-keys) 2) downto 1 do
	(setf state (inv-shift-rows state)
	      state (inv-mix-columns-sub-bytes state)
	      state (add-round-key state (aref expanded-decryption-keys i))))
      (setf state (inv-sub-bytes state)
	    state (inv-shift-rows state))
      (add-round-key state (aref expanded-decryption-keys 0)))))
