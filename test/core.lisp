;;;; test/core.lisp -- cl-smb against a real Samba: sbcl --script test/core.lisp
;;;;
;;;; The server (user cl-smb, password hunter2, share Public, signing mandatory) on 127.0.0.1:4450:
;;;;   see README.md.  Runs every check at 3.0.2 (AES-CMAC signing) and again at 2.1 (HMAC-SHA256).

(load "~/quicklisp/setup.lisp")
(let ((root (make-pathname :name nil :type nil :directory (butlast (pathname-directory *load-truename*) 2)
                           :defaults *load-truename*)))
  ;; the workspace: cl-smb's siblings (natrium, gossamer) beside it
  (dolist (d (directory (merge-pathnames "*/" root))) (push d asdf:*central-registry*)))
(require :sb-bsd-sockets)
(handler-bind ((warning #'muffle-warning)) (asdf:load-system :cl-smb))

(defvar *host* (or (sb-ext:posix-getenv "SMB_HOST") "127.0.0.1"))
(defvar *port* (parse-integer (or (sb-ext:posix-getenv "SMB_PORT") "4450")))
(defvar *user* (or (sb-ext:posix-getenv "SMB_USER") "cl-smb"))
(defvar *password* (or (sb-ext:posix-getenv "SMB_PASSWORD") "hunter2"))
(defvar *fails* 0)
(defvar *checks* 0)
(defun check (name ok &optional detail)
  (incf *checks*)
  (unless ok (incf *fails*))
  (format t "~&~:[FAIL~;ok  ~] ~a~@[ -- ~a~]~%" ok name (unless ok detail)))

(defun connect (&rest args)
  ;; ARGS first: a repeated keyword's first value is the one that counts
  (apply #'smb:smb-connect *host* (append args (list :port *port* :user *user* :password *password* :share "Public"))))

(defun md5-file (path)
  (with-open-file (in path :element-type '(unsigned-byte 8))
    (let ((v (make-array (file-length in) :element-type '(unsigned-byte 8))))
      (read-sequence v in) (natrium:md5 v))))

(defun suite (dialects label)
  (format t "~&--- ~a~%" label)
  (let ((s (connect :dialects dialects)) (tmp (format nil "/tmp/cl-smb-test-~d" (random 1000000))))
    (check "signed session" (smb:smb-session-signing-p s))
    (check "dialect" (member (smb:smb-session-dialect s) dialects) (smb:smb-session-dialect s))
    (let ((root (mapcar #'smb:smb-entry-name (smb:smb-list s "/"))))
      (check "root lists docs" (member "docs" root :test #'string=) root))
    (let ((e (smb:smb-stat s "/docs/big.bin")))
      (check "stat big.bin" (and e (= (smb:smb-entry-size e) 3145728) (not (smb:smb-entry-directory-p e))) e))
    (check "stat a folder" (smb:smb-entry-directory-p (smb:smb-stat s "/docs")))
    (check "stat missing is NIL" (null (smb:smb-stat s "/docs/nope.txt")))
    ;; a whole 3 MB file down, then up again under another name, then down again: same bytes
    (let ((got (smb:smb-get s "/docs/big.bin" (concatenate 'string tmp "-a"))))
      (check "get 3 MB" (= got 3145728) got))
    (smb:smb-mkdir s "/work")
    (check "mkdir" (smb:smb-entry-directory-p (smb:smb-stat s "/work")))
    (let ((ticks 0))
      (smb:smb-put s (concatenate 'string tmp "-a") "/work/copy.bin" :progress (lambda (n) (declare (ignore n)) (incf ticks)))
      (check "put 3 MB, with progress" (and (plusp ticks) (= 3145728 (smb:smb-entry-size (smb:smb-stat s "/work/copy.bin"))))))
    (smb:smb-get s "/work/copy.bin" (concatenate 'string tmp "-b"))
    (check "round trip is byte for byte" (equalp (md5-file (concatenate 'string tmp "-a")) (md5-file (concatenate 'string tmp "-b"))))
    (check "read-range in the middle"
           (equalp (smb:smb-read-range s "/work/copy.bin" 1000000 100)
                   (with-open-file (in (concatenate 'string tmp "-a") :element-type '(unsigned-byte 8))
                     (file-position in 1000000)
                     (let ((v (make-array 100 :element-type '(unsigned-byte 8)))) (read-sequence v in) v))))
    (smb:smb-write-range s "/work/note.txt" 0 (map '(vector (unsigned-byte 8)) #'char-code "héllo") :create t)
    (check "write-range creates" (= 5 (smb:smb-entry-size (smb:smb-stat s "/work/note.txt"))))
    (smb:smb-rename s "/work/note.txt" "/work/renamed ü.txt")
    (check "rename (a non-ASCII name)" (and (null (smb:smb-stat s "/work/note.txt")) (smb:smb-stat s "/work/renamed ü.txt")))
    (check "list sees the new names" (equal (sort (mapcar #'smb:smb-entry-name (smb:smb-list s "/work")) #'string<)
                                            '("copy.bin" "renamed ü.txt")))
    (check "rmdir of a full folder refuses"
           (handler-case (progn (smb:smb-rmdir s "/work") nil)
             (smb:smb-error (e) (= (smb:smb-error-status e) #xC0000101))))
    (smb:smb-delete s "/work/copy.bin")
    (smb:smb-delete s "/work/renamed ü.txt")
    (smb:smb-rmdir s "/work")
    (check "delete and rmdir" (null (smb:smb-stat s "/work")))
    (multiple-value-bind (total free) (smb:smb-statvfs s)
      (check "statvfs" (and (plusp total) (<= 0 free total)) (list total free)))
    (smb:smb-disconnect s)
    (ignore-errors (delete-file (concatenate 'string tmp "-a")))
    (ignore-errors (delete-file (concatenate 'string tmp "-b")))))

(suite '(#x0202 #x0210 #x0300 #x0302) "SMB 3.0.2, AES-CMAC signing")
(suite '(#x0202 #x0210) "SMB 2.1, HMAC-SHA256 signing")

(format t "~&--- logon failures~%")
(check "a wrong password is an auth error"
       (handler-case (progn (smb:smb-connect *host* :port *port* :user *user* :password "nope" :share "Public") nil)
         (smb:smb-auth-error () t)))
(check "a missing share says so"
       (handler-case (progn (connect :share "Nope") nil)
         (smb:smb-error (e) (= (smb:smb-error-status e) #xC00000CC))))

(format t "~&~d checks, ~d failed~%" *checks* *fails*)
(sb-ext:exit :code (if (zerop *fails*) 0 1))
