;;; Benchmarks

(defparameter *block-length* 100000)
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
    (format t "~&~16,'0X~%" (aref text i))))

(defun benchmark-encrypt-ecb ()
  (let ((aes (make-instance 'aes:aes-128 :cipher-key *key*)))
    (loop for i below *block-length* do
      (setf (aref *cipher-text* i) (aes:encode aes (aref *plain-text* i))))))

#+(or)(defun benchmark-encrypt-ecb ()
  (aes:block-encrypt-ecb *plain-text* *cipher-text* *key*)
  (values))

#+(or)(defun benchmark-encrypt-cbc ()
  (aes:block-encrypt-cbc *plain-text* *cipher-text* *key* :iv *iv*)
  (values))

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
