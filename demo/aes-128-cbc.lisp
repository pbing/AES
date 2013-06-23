;;;; Decode an AES-128 file created by OpenSSL

(defun aes-128-cbc-decode-file ()
  "See files message.txt encode.sh and keys.txt for creation of message.cpt."
  (let ((file-name #p"message.cpt")
	(key       #x06C219E5BC8378F3A8A3F83B4B7E4649)
	(iv        #x09B01182A7D342365DD9F8D4AD437DF1))
    (with-open-file (stream file-name :element-type '(unsigned-byte 128))
      (let* ((file-length (file-length stream))
	     (cipher (make-array file-length :element-type '(unsigned-byte 128)))
	     (plain  (make-array file-length :element-type '(unsigned-byte 128)))
	     (aes (make-instance 'aes:aes-128 :cipher-key key)))

	;; slurp in file
	(loop for i below file-length do
	  (setf (aref cipher i) (read-byte stream)))

	;; decode
	(aes:block-decrypt-cbc aes cipher plain :iv iv)

	;; print
	(loop for pt across plain do
	  (loop for i from 120 downto 0 by 8 do
	    (format t "~X" (code-char (ldb (byte 8 i) pt)))))))))
