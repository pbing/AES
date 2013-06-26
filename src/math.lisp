;;;; Galois math

(in-package #:aes)

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
