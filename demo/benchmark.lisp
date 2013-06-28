;;; Benchmarks

(defparameter *block-length* 1000000)
(defparameter *key* (random (expt 2 128)))
(defparameter *iv* (random (expt 2 128)))

(defparameter *plain-text*   (make-array *block-length* :element-type '(unsigned-byte 128)))
(defparameter *cipher-text*  (make-array *block-length* :element-type '(unsigned-byte 128)))
(defparameter *scratch-text* (make-array *block-length* :element-type '(unsigned-byte 128)))

(defun init-text (text)
  (loop for i below (length text) do
    (setf (aref text i) i)))

(defun clear-text (text)
  (loop for i below (length text) do
    (setf (aref text i) 0)))

(defun print-text (text &optional (n 10))
  (setf n (or n (length text)))
  (loop for i below n do
    (format t "~&~32,'0X~%" (aref text i))))

(defun benchmark-128-encrypt-ecb ()
  (let ((aes (make-instance 'aes:aes-128 :cipher-key *key*)))
    (aes:block-encrypt-ecb aes *plain-text* *cipher-text*)
    (values)))

(defun benchmark-192-encrypt-ecb ()
  (let ((aes (make-instance 'aes:aes-192 :cipher-key *key*)))
    (aes:block-encrypt-ecb aes *plain-text* *cipher-text*)
    (values)))

(defun benchmark-256-encrypt-ecb ()
  (let ((aes (make-instance 'aes:aes-256 :cipher-key *key*)))
    (aes:block-encrypt-ecb aes *plain-text* *cipher-text*)
    (values)))

(defun benchmark-128-encrypt-cbc ()
  (let ((aes (make-instance 'aes:aes-128 :cipher-key *key*)))
    (aes:block-encrypt-cbc aes *plain-text* *cipher-text* *iv*)
    (values)))

(defun benchmark-192-encrypt-cbc ()
  (let ((aes (make-instance 'aes:aes-192 :cipher-key *key*)))
    (aes:block-encrypt-cbc aes *plain-text* *cipher-text* *iv*)
    (values)))

(defun benchmark-256-encrypt-cbc ()
  (let ((aes (make-instance 'aes:aes-256 :cipher-key *key*)))
    (aes:block-encrypt-cbc aes *plain-text* *cipher-text* *iv*)
    (values)))

(defun benchmark-128-decrypt-ecb ()
  (let ((aes (make-instance 'aes:aes-128 :cipher-key *key*)))
    (aes:block-decrypt-ecb aes *plain-text* *cipher-text*)
    (values)))

(defun benchmark-192-decrypt-ecb ()
  (let ((aes (make-instance 'aes:aes-192 :cipher-key *key*)))
    (aes:block-decrypt-ecb aes *plain-text* *cipher-text*)
    (values)))

(defun benchmark-256-decrypt-ecb ()
  (let ((aes (make-instance 'aes:aes-256 :cipher-key *key*)))
    (aes:block-decrypt-ecb aes *plain-text* *cipher-text*)
    (values)))

(defun benchmark-128-decrypt-cbc ()
  (let ((aes (make-instance 'aes:aes-128 :cipher-key *key*)))
    (aes:block-decrypt-cbc aes *plain-text* *cipher-text* *iv*)
    (values)))

(defun benchmark-192-decrypt-cbc ()
  (let ((aes (make-instance 'aes:aes-192 :cipher-key *key*)))
    (aes:block-decrypt-cbc aes *plain-text* *cipher-text* *iv*)
    (values)))

(defun benchmark-256-decrypt-cbc ()
  (let ((aes (make-instance 'aes:aes-256 :cipher-key *key*)))
    (aes:block-decrypt-cbc aes *plain-text* *cipher-text* *iv*)
    (values)))

(init-text *plain-text*)

#+(or)
(sb-profile:profile "AES")
;;; (sb-profile:report)
;;; (sb-profile:reset)
;;; (sb-profile:unprofile)


;;; (require :sb-sprof)
#+(or)
(sb-sprof:with-profiling (:max-samples 1000
                          :mode :time
                          :report :flat)
  (benchmark-encrypt-ecb))
