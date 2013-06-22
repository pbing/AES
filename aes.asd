;;;; Advanced Encryptions Standard (AES)

(defsystem aes
  :components ((:file "packages")
	       (:file "aes" :depends-on ("packages"))))

;;; Usage:
;;;   (asdf:load-system :aes-tests)
;;;   (sb-rt:do-tests)
(defsystem aes-tests
  :depends-on (aes sb-rt)
  :components ((:file "packages")
	       (:file "aes-tests" :depends-on ("packages"))))

;;; Local Variables:
;;; mode: Lisp
;;; End:
