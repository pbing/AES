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
  ((expanded-keys :type (simple-array (unsigned-byte 128)))))

(defclass aes-128 (aes) 
  ((cipher-key :type (unsigned-byte 128) :initarg :cipher-key)))

(defclass aes-192 (aes)
  ((cipher-key :type (unsigned-byte 192) :initarg :cipher-key)))

(defclass aes-256 (aes)
  ((cipher-key :type (unsigned-byte 256) :initarg :cipher-key)))

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

(defgeneric encrypt (o n))
(defmethod encrypt ((o aes) n)
  (with-slots (expanded-keys state) o
    (let ((state (add-round-key n (aref expanded-keys 0))))
      (declare (type (unsigned-byte 128) state))
      (loop for i from 1 below (1- (length expanded-keys)) do
	(setf state (sub-bytes state)
	      state (shift-rows state)
	      state (mix-columns state)
	      state (add-round-key state (aref expanded-keys i))))
      (setf state (sub-bytes state)
	    state (shift-rows state))
      (add-round-key state (aref expanded-keys (1- (length expanded-keys)))))))

(defgeneric decrypt (o n))
(defmethod decrypt ((o aes) n)
  (with-slots (expanded-keys state) o
    (let ((state (add-round-key n (aref expanded-keys (1- (length expanded-keys))))))
      (declare (type (unsigned-byte 128) state))
      (loop for i from (- (length expanded-keys) 2) downto 1 do
	(setf state (inv-shift-rows state)
	      state (inv-sub-bytes state)
	      state (add-round-key state (aref expanded-keys i))
	      state (inv-mix-columns state)))
      (setf state (inv-shift-rows state)
	    state (inv-sub-bytes state))
      (add-round-key state (aref expanded-keys 0)))))
