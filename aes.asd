;;;; Advanced Encryptions Standard (AES)

(defsystem aes
  :in-order-to ((test-op (test-op aes-tests)))
  :pathname "src"
  :components ((:file "packages")
	       (:file "aes" :depends-on ("packages"))
	       (:file "block" :depends-on ("packages"))))

;;; for test do: (asdf:test-system :aes)
(defsystem aes-tests
  :depends-on (aes sb-rt)
  :pathname "tests"
  :components ((:file "aes-tests")))

(defmethod perform ((o test-op) (s (eql (find-system :aes))))
  (funcall (intern "DO-TESTS" "SB-RT"))
  t)

;;; Local Variables:
;;; mode: Lisp
;;; End:
