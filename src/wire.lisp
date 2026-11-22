;;;; wire.lisp -- bytes: little-endian integers, UTF-16LE, a growable buffer, DER for SPNEGO.

(in-package #:cl-smb)

(deftype octets () '(simple-array (unsigned-byte 8) (*)))

(defun octets (n) (make-array n :element-type '(unsigned-byte 8) :initial-element 0))

(defun u16 (v i) (logior (aref v i) (ash (aref v (+ i 1)) 8)))
(defun u32 (v i) (logior (u16 v i) (ash (u16 v (+ i 2)) 16)))
(defun u64 (v i) (logior (u32 v i) (ash (u32 v (+ i 4)) 32)))

(defun put-u16 (v i x) (setf (aref v i) (ldb (byte 8 0) x) (aref v (+ i 1)) (ldb (byte 8 8) x)) v)
(defun put-u32 (v i x) (put-u16 v i (ldb (byte 16 0) x)) (put-u16 v (+ i 2) (ldb (byte 16 16) x)) v)
(defun put-u64 (v i x) (put-u32 v i (ldb (byte 32 0) x)) (put-u32 v (+ i 4) (ldb (byte 32 32) x)) v)

(defun cat (&rest vs)
  "The octet vectors VS, end to end, in a fresh one."
  (let ((out (octets (reduce #'+ vs :key #'length))) (i 0))
    (dolist (v vs out) (replace out v :start1 i) (incf i (length v)))))

(defun le16 (x) (put-u16 (octets 2) 0 x))
(defun le32 (x) (put-u32 (octets 4) 0 x))
(defun le64 (x) (put-u64 (octets 8) 0 x))
(defun be32 (x) (let ((v (octets 4))) (dotimes (k 4 v) (setf (aref v k) (ldb (byte 8 (* 8 (- 3 k))) x)))))

(defun utf16le (string)
  "STRING as UTF-16LE octets (a character past the BMP as its surrogate pair)."
  (let ((units '()))
    (loop for ch across string
          for c = (char-code ch)
          do (if (< c #x10000)
                 (push c units)
                 (let ((c2 (- c #x10000)))
                   (push (+ #xD800 (ash c2 -10)) units)
                   (push (+ #xDC00 (logand c2 #x3FF)) units))))
    (let ((out (octets (* 2 (length units)))) (i 0))
      (dolist (u (nreverse units) out) (put-u16 out i u) (incf i 2)))))

(defun from-utf16le (v &optional (start 0) (end (length v)))
  "The string UTF-16LE octets V[START..END) spell."
  (with-output-to-string (s)
    (loop with i = start
          while (< (1+ i) end)
          do (let ((u (u16 v i)))
               (incf i 2)
               (if (and (<= #xD800 u #xDBFF) (< (1+ i) end))
                   (let ((lo (u16 v i)))
                     (incf i 2)
                     (write-char (code-char (+ #x10000 (ash (- u #xD800) 10) (- lo #xDC00))) s))
                   (write-char (code-char u) s))))))

(defun ascii (string) (map 'octets #'char-code string))

;;; DER, for the SPNEGO wrapper around NTLMSSP (RFC 4178): only what that needs.

(defun der-length (n)
  (if (< n 128)
      (octets-of n)
      (let ((bytes (loop for x = n then (ash x -8) while (plusp x) collect (logand x #xff))))
        (apply #'octets-of (logior #x80 (length bytes)) (reverse bytes)))))

(defun octets-of (&rest bytes) (map 'octets #'identity bytes))

(defun der (tag &rest contents)
  "A DER element: TAG, its length, and CONTENTS (octet vectors) end to end."
  (let ((body (apply #'cat contents)))
    (cat (octets-of tag) (der-length (length body)) body)))

(defun der-children (v start end)
  "The (TAG CONTENT-START CONTENT-END) of each element in V[START..END)."
  (loop with i = start
        while (< i end)
        collect (let ((tag (aref v i)) (len (aref v (1+ i))) (p (+ i 2)))
                  (when (>= len #x80)
                    (let ((k (logand len #x7f)))
                      (setf len 0)
                      (dotimes (j k) (setf len (logior (ash len 8) (aref v (+ p j)))))
                      (incf p k)))
                  (prog1 (list tag p (+ p len)) (setf i (+ p len))))))

(defun der-find (v start end &rest path)
  "Follow PATH (tags) down through V's elements from [START,END): the (START END) of the last one's
   contents, or NIL."
  (if (null path)
      (list start end)
      (let ((hit (find (first path) (der-children v start end) :key #'first)))
        (and hit (apply #'der-find v (second hit) (third hit) (rest path))))))
