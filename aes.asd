;;; -*- Lisp -*-

(defsystem aes
  :components ((:file "aes")))

;; (asdf:load-system :aes-tests)
;; (sb-rt:do-tests)
(defsystem aes-tests
  :depends-on (aes sb-rt)
  :components ((:file "aes-tests")))
