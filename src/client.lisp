;;;; client.lisp -- an SMB2 session on one share (MS-SMB2), and the file operations on it.
;;;;
;;;; One request in flight at a time, no compounding: a file manager's traffic, not a NAS benchmark.
;;;; Every request after the logon is signed when the session has a key: HMAC-SHA256 for 2.0.2 and
;;;; 2.1, AES-CMAC with the SP 800-108 derived key from 3.0 (MS-SMB2 3.1.4.1, 3.2.5.3.1).  Responses'
;;;; signatures are checked.  A share that demands encryption is refused with a clear error rather
;;;; than spoken to in the clear.

(in-package #:cl-smb)

(define-condition smb-error (error)
  ((status :initarg :status :initform 0 :reader smb-error-status)
   (message :initarg :message :initform nil :reader smb-error-message))
  (:report (lambda (c s) (format s "SMB: ~a" (or (smb-error-message c) (status-text (smb-error-status c)))))))

(define-condition smb-auth-error (smb-error) ())

(defvar *wait-hook* nil
  "When non-NIL, a function of no arguments called while waiting on the network (a UI's chance to
   breathe).  Called between reads, never inside one.")

(defparameter +statuses+
  '((#x00000000 . "success") (#xC0000016 . "more processing required") (#x00000103 . "pending")
    (#x80000006 . "no more files") (#xC0000011 . "end of file")
    (#xC0000034 . "no such file or folder") (#xC000003A . "no such folder") (#xC0000022 . "access denied")
    (#xC000006D . "the user name or password is wrong") (#xC0000035 . "it already exists")
    (#xC00000CC . "no such share") (#xC0000101 . "the folder is not empty")
    (#xC0000103 . "not a folder") (#xC00000BA . "that is a folder") (#xC0000043 . "it is in use")
    (#xC0000033 . "that name is not allowed") (#xC000007F . "the disk is full")
    (#xC0000072 . "the account is disabled") (#xC0000071 . "the password has expired")
    (#xC0000224 . "the password must be changed") (#xC000015B . "this kind of logon is not allowed")
    (#xC00000BB . "the server does not support that") (#xC0000010 . "the server does not support that")
    (#xC0000005 . "the server refused (access violation)") (#xC000000D . "the server rejected a parameter")))

(defun status-text (status)
  (or (cdr (assoc status +statuses+)) (format nil "status #x~8,'0x" status)))

;;; ---- the connection ----------------------------------------------------------------------------

(defstruct (smb-session (:constructor %make-session))
  socket stream host share
  (next-mid 0) (credits 1) (session-id 0) (tree-id 0)
  dialect (max-read 65536) (max-write 65536)
  key signing-key signing-p
  server-signing-required
  ;; reused for every message, so a megabyte moved is not megabytes of garbage
  (send-buf (octets 0)) (recv-buf (octets 0)))

(defun %room (v n)
  "V if it holds N bytes, else a bigger one (twice, to grow seldom)."
  (if (>= (length v) n) v (octets (max n (* 2 (length v))))))

(defun %resolve (host)
  (handler-case (sb-bsd-sockets:make-inet-address host)
    (error () (sb-bsd-sockets:host-ent-address (sb-bsd-sockets:get-host-by-name host)))))

(defun %tcp-connect (host port)
  (let ((sock (make-instance 'sb-bsd-sockets:inet-socket :type :stream :protocol :tcp)))
    (sb-bsd-sockets:socket-connect sock (%resolve host) port)
    (values sock (sb-bsd-sockets:socket-make-stream sock :input t :output t
                                                         :element-type '(unsigned-byte 8)
                                                         :buffering :full))))

(defun %read-exactly (stream n &optional (v (octets n)))
  "N bytes from STREAM into V (fresh unless given, then at its start)."
  (let ((got 0))
    (loop while (< got n)
          do (let ((k (read-sequence v stream :start got :end n)))
               (when (= k got) (error 'smb-error :message "the server closed the connection"))
               (setf got k)))
    v))

(defun %send-frame (s msg &optional (n (length msg)))
  "MSG's first N bytes with their 4-byte Direct TCP length (a zero byte, then 24 bits big-endian)."
  (let ((st (smb-session-stream s)))
    (write-sequence (octets-of 0 (ldb (byte 8 16) n) (ldb (byte 8 8) n) (ldb (byte 8 0) n)) st)
    (write-sequence msg st :end n)
    (finish-output st)))

(defun %recv-frame (s &optional reuse)
  "The next frame: (values bytes length).  REUSE: into the session's receive buffer (good until the next
   frame), else a fresh vector of its own."
  (when *wait-hook* (funcall *wait-hook*))
  (let* ((st (smb-session-stream s)) (hd (%read-exactly st 4))
         (n (logior (ash (aref hd 1) 16) (ash (aref hd 2) 8) (aref hd 3))))
    (if reuse
        (let ((buf (setf (smb-session-recv-buf s) (%room (smb-session-recv-buf s) n))))
          (values (%read-exactly st n buf) n))
        (values (%read-exactly st n) n))))

;;; ---- the header and signing ----------------------------------------------------------------------

(defconstant +flag-response+ 1)
(defconstant +flag-async+ 2)
(defconstant +flag-signed+ 8)

(defun %kdf (key label context)
  "SP 800-108 in counter mode with HMAC-SHA256, one block, L = 128 (MS-SMB2 3.1.4.2)."
  (subseq (natrium:hmac-sha256 key (cat (be32 1) label (octets 1) context (be32 128))) 0 16))

(defun %signature (s msg &optional (n (length msg)))
  "The 16-byte signature of MSG's first N bytes under S's key.  Its signature field must be zero."
  (if (>= (smb-session-dialect s) #x0300)
      (natrium:aes-cmac (smb-session-signing-key s) msg :end n)
      (subseq (natrium:hmac-sha256 (smb-session-signing-key s) (if (= n (length msg)) msg (subseq msg 0 n))) 0 16)))

(defun %signature-ok-p (s r n)
  "Whether the frame R (N long) carries S's signature: checked in place (the field is zeroed to check)."
  (let ((sig (subseq r 48 64)))
    (fill r 0 :start 48 :end 64)
    (equalp sig (%signature s r n))))

(defun %header (s command charge &key (tree-id (smb-session-tree-id s)))
  (let ((h (octets 64)))
    (replace h (octets-of #xFE (char-code #\S) (char-code #\M) (char-code #\B)))
    (put-u16 h 4 64)
    (put-u16 h 6 charge)
    (put-u16 h 12 command)
    (put-u16 h 14 (max 64 charge))                    ; credits asked for
    (put-u64 h 24 (smb-session-next-mid s))
    (put-u32 h 32 #xFEFF)                             ; reserved (process id)
    (put-u32 h 36 tree-id)
    (put-u64 h 40 (smb-session-session-id s))
    h))

(defun %request (s command body &key (charge 1) (sign (smb-session-signing-p s)) (ok '(0)) tree-id
                                     data (start 0) (end (and data (length data))) raw)
  "Send COMMAND with BODY, then DATA[START,END) if given (a write's bytes, not copied out first);
   (values STATUS RESPONSE-BODY HEADER).  RAW (a read's big answer): (values STATUS FRAME LENGTH), the
   frame in the session's receive buffer, good until the next request.  Signals SMB-ERROR unless the
   status is in OK.  CHARGE is the request's credit charge (a large read or write costs one per 64 KB)."
  (let* ((header (if tree-id (%header s command charge :tree-id tree-id) (%header s command charge)))
         (n (+ 64 (length body) (if data (- end start) 0)))
         (msg (setf (smb-session-send-buf s) (%room (smb-session-send-buf s) n)))
         (mid (smb-session-next-mid s)))
    (replace msg header)
    (replace msg body :start1 64)
    (when data (replace msg data :start1 (+ 64 (length body)) :start2 start :end2 end))
    (when sign
      (put-u32 msg 16 (logior (u32 msg 16) +flag-signed+))
      (replace msg (%signature s msg n) :start1 48))
    (incf (smb-session-next-mid s) charge)
    (decf (smb-session-credits s) charge)
    (%send-frame s msg n)
    (loop
      (multiple-value-bind (r rn) (%recv-frame s raw)
       (let ((status (u32 r 8)) (flags (u32 r 16)))
        (unless (and (>= rn 64) (= (aref r 0) #xFE))
          (error 'smb-error :message "the server answered with something that is not SMB2"))
        (incf (smb-session-credits s) (u16 r 14))
        (cond ((/= (u64 r 24) mid))                   ; not ours (an oplock break we did not ask for)
              ((and (= status #x103) (logtest flags +flag-async+)))   ; interim: the answer follows
              (t
               (when (and (smb-session-signing-p s) (logtest flags +flag-signed+)
                          (not (%signature-ok-p s r rn)))
                 (error 'smb-error :message "a reply's signature does not match: the connection is not safe"))
               (unless (member status ok)
                 (error (if (member status '(#xC000006D #xC0000072 #xC0000071 #xC0000224 #xC000015B))
                            'smb-auth-error 'smb-error)
                        :status status))
               (return (if raw (values status r rn) (values status (subseq r 64 rn) r))))))))))

;;; ---- negotiate, logon, share ---------------------------------------------------------------------

(defparameter *dialects* '(#x0202 #x0210 #x0300 #x0302)
  "The SMB dialects offered: 2.0.2, 2.1, 3.0, 3.0.2.  3.1.1 needs preauthentication integrity, and
   its signing of the logon, which this client does not do yet.")

(defun %negotiate (s dialects)
  (let* (
         (body (apply #'cat
                      (le16 36) (le16 (length dialects)) (le16 1) (le16 0)   ; signing enabled
                      (le32 #x4)                                            ; LARGE_MTU
                      (natrium:random-bytes 16) (octets 8)
                      (mapcar #'le16 dialects))))
    (multiple-value-bind (status r) (%request s 0 body :sign nil)
      (declare (ignore status))
      (setf (smb-session-dialect s) (u16 r 4)
            (smb-session-server-signing-required s) (logtest (u16 r 2) 2)
            (smb-session-max-read s) (min (u32 r 32) (* 1024 1024))
            (smb-session-max-write s) (min (u32 r 36) (* 1024 1024)))
      (unless (member (smb-session-dialect s) dialects)
        (error 'smb-error :message (format nil "the server chose an SMB dialect this client does not speak (#x~4,'0x)"
                                           (smb-session-dialect s)))))))

(defun %session-setup (s token)
  "One SESSION_SETUP leg with security TOKEN: (values STATUS SERVER-TOKEN SESSION-FLAGS)."
  (let ((body (cat (le16 25) (octets-of 0 1) (le32 0) (le32 0)
                   (le16 88) (le16 (length token)) (le64 0) token)))
    (multiple-value-bind (status r header) (%request s 1 body :sign nil :ok '(0 #xC0000016))
      ;; the server names the session in its first answer; every later request carries it
      (setf (smb-session-session-id s) (u64 header 40))
      (values status (subseq r (- (u16 r 4) 64) (+ (- (u16 r 4) 64) (u16 r 6))) (u16 r 2)))))

(defun %logon (s user password domain)
  (multiple-value-bind (status blob) (%session-setup s (spnego-init (ntlm-negotiate)))
    (unless (= status #xC0000016)
      (error 'smb-auth-error :status status :message "the server did not offer an NTLM logon"))
    (let ((challenge (spnego-token blob)))
      (unless challenge (error 'smb-auth-error :message "the server's logon challenge could not be read"))
      (multiple-value-bind (auth key) (ntlm-authenticate user password domain challenge)
        (multiple-value-bind (status2 blob2 flags) (%session-setup s (spnego-response auth))
          (declare (ignore status2))
          (unless (spnego-accepted-p blob2)
            (error 'smb-auth-error :message "the server did not accept the logon"))
          (let ((guest (logtest flags 3)))             ; IS_GUEST or IS_NULL: no key to sign with
            (when (and guest (smb-session-server-signing-required s))
              (error 'smb-auth-error :message "the server let us in only as a guest, but requires signing"))
            (unless guest
              (setf (smb-session-key s) key
                    (smb-session-signing-key s)
                    (if (>= (smb-session-dialect s) #x0300)
                        (natrium:make-aes-key (gossamer:fixed-copy
                                               (%kdf key (ascii (format nil "SMB2AESCMAC~c" (code-char 0)))
                                                     (ascii (format nil "SmbSign~c" (code-char 0))))))
                        key)
                    (smb-session-signing-p s) t))))))))

(defun %tree-connect (s share)
  (let* ((path (utf16le (format nil "\\\\~a\\~a" (smb-session-host s) share)))
         (body (cat (le16 9) (le16 0) (le16 72) (le16 (length path)) path)))
    (multiple-value-bind (status r header) (%request s 3 body :tree-id 0)
      (declare (ignore status))
      (when (logtest (u32 r 4) #x8000)
        (error 'smb-error :message (format nil "the share ~a requires encryption, which this client does not do yet" share)))
      (setf (smb-session-tree-id s) (u32 header 36)))))

(defun smb-connect (host &key (port 445) (user "") (password "") (domain "") share (dialects *dialects*))
  "Log on to HOST as USER (in DOMAIN, \"\" for a stand-alone server) and connect to SHARE.  A session.
   DIALECTS limits what is offered (a test of the 2.x signing, say)."
  (multiple-value-bind (sock stream) (%tcp-connect host port)
    (let ((s (%make-session :socket sock :stream stream :host host :share share)))
      (handler-bind ((error (lambda (e) (declare (ignore e)) (ignore-errors (sb-bsd-sockets:socket-close sock)))))
        (%negotiate s dialects)
        (%logon s user password domain)
        (%tree-connect s share)
        s))))

(defun smb-disconnect (s)
  (ignore-errors (%request s 4 (cat (le16 4) (le16 0))))         ; TREE_DISCONNECT
  (ignore-errors (%request s 2 (cat (le16 4) (le16 0))))         ; LOGOFF
  (ignore-errors (sb-bsd-sockets:socket-close (smb-session-socket s)))
  (when (and (smb-session-signing-key s) (>= (smb-session-dialect s) #x0300))
    (ignore-errors (natrium:aes-key-wipe (smb-session-signing-key s))))
  nil)

;;; ---- paths, files and handles ----------------------------------------------------------------------

(defun %smb-path (path)
  "A POSIX-style PATH (\"/docs/a.txt\", \"\" or \"/\" for the share's root) as the share-relative,
   backslashed name CREATE takes."
  (let ((p (string-trim "/" path)))
    (substitute #\\ #\/ p)))

(defconstant +read-access+ #x00120089)        ; READ_DATA | READ_EA | READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
(defconstant +write-access+ #x00120196)       ; WRITE_DATA | APPEND | WRITE_EA | WRITE_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
(defconstant +delete-access+ #x00110080)      ; DELETE | READ_ATTRIBUTES | SYNCHRONIZE

(defun %create (s path &key (access +read-access+) (disposition 1) (options 0) (attributes 0))
  "Open PATH: (values FILE-ID RESPONSE).  DISPOSITION 1 open, 2 create, 5 overwrite-or-create."
  (let* ((name (utf16le (%smb-path path)))
         (body (cat (le16 57) (octets-of 0 0) (le32 2) (le64 0) (le64 0)
                    (le32 access) (le32 attributes) (le32 7)          ; share read, write and delete
                    (le32 disposition) (le32 options)
                    (le16 120) (le16 (length name)) (le32 0) (le32 0)
                    (if (zerop (length name)) (octets 1) name))))
    (multiple-value-bind (status r) (%request s 5 body)
      (declare (ignore status))
      (values (subseq r 64 80) r))))

(defun %close (s fid)
  (%request s 6 (cat (le16 24) (le16 0) (le32 0) fid)))

(defmacro with-handle ((fid s path &rest create-args) &body body)
  `(let ((,fid (%create ,s ,path ,@create-args)))
     (unwind-protect (progn ,@body) (ignore-errors (%close ,s ,fid)))))

(defun filetime->unix (ft) (if (zerop ft) 0 (- (floor ft 10000000) 11644473600)))

(defstruct (smb-entry (:constructor %make-entry (name directory-p size mtime attributes)))
  name directory-p size mtime attributes)

(defun smb-stat (s path)
  "PATH's entry, or NIL when there is none."
  (handler-case
      (multiple-value-bind (fid r) (%create s path :access #x00100080)   ; READ_ATTRIBUTES | SYNCHRONIZE
        (%close s fid)
        (let ((attrs (u32 r 56)))
          (%make-entry (let ((p (string-right-trim "/" path))) (subseq p (1+ (or (position #\/ p :from-end t) -1))))
                       (logtest attrs #x10) (u64 r 48) (filetime->unix (u64 r 24)) attrs)))
    (smb-error (e)
      (if (member (smb-error-status e) '(#xC0000034 #xC000003A)) nil (error e)))))

;;; ---- directories ---------------------------------------------------------------------------------

(defun smb-map-entries (s path fn)
  "Call FN with each SMB-ENTRY in the folder PATH (not . or ..), a batch at a time as they arrive."
  (with-handle (fid s path :access #x00100081 :options 1)       ; LIST_DIRECTORY | READ_ATTRIBUTES; a directory
    (let ((pattern (utf16le "*")) (first t))
      (loop
        (multiple-value-bind (status r)
            (%request s 14 (cat (le16 33) (octets-of 1 (if first 1 0)) (le32 0) fid   ; FileDirectoryInformation
                                (le16 96) (le16 (length pattern)) (le32 65536) pattern)
                      :ok '(0 #x80000006))
          (setf first nil)
          (when (= status #x80000006) (return))
          (let* ((off (- (u16 r 2) 64)) (len (u32 r 4)) (buf (subseq r off (+ off len))) (i 0))
            (loop
              (let* ((next (u32 buf i))
                     (attrs (u32 buf (+ i 56)))
                     (nlen (u32 buf (+ i 60)))
                     (name (from-utf16le buf (+ i 64) (+ i 64 nlen))))
                (unless (member name '("." "..") :test #'string=)
                  (funcall fn (%make-entry name (logtest attrs #x10) (u64 buf (+ i 40))
                                           (filetime->unix (u64 buf (+ i 24))) attrs)))
                (when (zerop next) (return))
                (incf i next)))))))))

(defun smb-list (s path)
  "The SMB-ENTRYs of the folder PATH."
  (let ((out '()))
    (smb-map-entries s path (lambda (e) (push e out)))
    (nreverse out)))

;;; ---- reading and writing --------------------------------------------------------------------------

(defun %charge (s n)
  (if (>= (smb-session-dialect s) #x0210) (max 1 (ceiling n 65536)) 1))

(defun %chunk (s limit)
  "How many bytes one READ or WRITE may move now: the negotiated limit, and the credits in hand."
  (let ((by-credits (if (>= (smb-session-dialect s) #x0210) (* 65536 (max 1 (smb-session-credits s))) 65536)))
    (min limit by-credits)))

(defun %read-in-place (s fid offset n)
  "Up to N bytes at OFFSET, where they arrived: (values FRAME START END) -- the session's receive buffer,
   good until the next request; START = END at the end of the file."
  (multiple-value-bind (status r)
      (%request s 8 (cat (le16 49) (octets-of #x50 0) (le32 n) (le64 offset) fid
                         (le32 0) (le32 0) (le32 0) (le16 0) (le16 0) (octets 1))
                :charge (%charge s n) :ok '(0 #xC0000011) :raw t)
    (if (= status #xC0000011)
        (values r 0 0)
        (let ((off (aref r (+ 64 2)))) (values r off (+ off (u32 r (+ 64 4))))))))

(defun %read (s fid offset n)
  "Up to N bytes at OFFSET: an octet vector, empty at the end of the file."
  (multiple-value-bind (r start end) (%read-in-place s fid offset n)
    (subseq r start end)))

(defun %read-file (s path fn offset)
  "FN called with (frame start end) for each piece of PATH from OFFSET, in place; the total."
  (with-handle (fid s path)
    (let ((at offset))
      (loop (multiple-value-bind (r start end) (%read-in-place s fid at (%chunk s (smb-session-max-read s)))
              (when (= start end) (return (- at offset)))
              (funcall fn r start end)
              (incf at (- end start)))))))

(defun smb-read-range (s path offset length)
  "LENGTH bytes of PATH from OFFSET (fewer at its end)."
  (with-handle (fid s path)
    (let ((parts '()) (got 0))
      (loop while (< got length)
            do (let ((v (%read s fid (+ offset got) (min (- length got) (%chunk s (smb-session-max-read s))))))
                 (when (zerop (length v)) (return))
                 (push v parts) (incf got (length v))))
      (apply #'cat (nreverse parts)))))

(defun smb-read-file (s path fn &key (offset 0))
  "Call FN with each piece of PATH (an octet vector) from OFFSET to its end, in order.  The total."
  (%read-file s path (lambda (r start end) (funcall fn (subseq r start end))) offset))

(defun smb-get (s path local &key progress)
  "Copy PATH to the LOCAL file.  PROGRESS, if given, is called with the bytes so far.  The size."
  (with-open-file (out local :direction :output :if-exists :supersede :element-type '(unsigned-byte 8))
    (let ((done 0))
      (%read-file s path (lambda (r start end) (write-sequence r out :start start :end end) (incf done (- end start))
                           (when progress (funcall progress done)))
                  0)
      done)))

(defun %write (s fid offset data start end)
  (let ((n (- end start)))
    (multiple-value-bind (status r)
        (%request s 9 (cat (le16 49) (le16 112) (le32 n) (le64 offset) fid
                           (le32 0) (le32 0) (le16 0) (le16 0) (le32 0))
                  :data data :start start :end end :charge (%charge s n))
      (declare (ignore status))
      (u32 r 4))))

(defun smb-write-range (s path offset data &key (create nil))
  "Write the octet vector DATA into PATH at OFFSET (CREATE: make or truncate it first)."
  (with-handle (fid s path :access +write-access+ :disposition (if create 5 1) :options #x40)
    (let ((i 0))
      (loop while (< i (length data))
            do (let ((n (min (- (length data) i) (%chunk s (smb-session-max-write s)))))
                 (incf i (%write s fid (+ offset i) data i (+ i n)))))
      i)))

(defun smb-put (s local path &key progress)
  "Copy the LOCAL file to PATH, replacing it.  PROGRESS, if given, is called with the bytes so far."
  (with-open-file (in local :element-type '(unsigned-byte 8))
    (with-handle (fid s path :access +write-access+ :disposition 5 :options #x40)
      (let* ((chunk (%chunk s (smb-session-max-write s))) (buf (octets chunk)) (at 0))
        (loop (let ((n (read-sequence buf in)))
                (when (zerop n) (return at))
                (let ((i 0)) (loop while (< i n) do (incf i (%write s fid (+ at i) buf i n))))
                (incf at n)
                (when progress (funcall progress at))))))))

;;; ---- changing the tree ----------------------------------------------------------------------------

(defun smb-mkdir (s path)
  (%close s (%create s path :access #x00100081 :disposition 2 :options 1 :attributes #x10)))

(defun %set-info (s fid class buffer)
  (%request s 17 (cat (le16 33) (octets-of 1 class) (le32 (length buffer)) (le16 96) (le16 0) (le32 0) fid buffer)))

(defun %delete (s path options)
  (with-handle (fid s path :access +delete-access+ :options options)
    (%set-info s fid 13 (octets-of 1))))            ; FileDispositionInformation: delete on close

(defun smb-delete (s path) (%delete s path #x40))
(defun smb-rmdir (s path) (%delete s path #x1))

(defun smb-set-mtime (s path mtime)
  "Set PATH's last-write time to MTIME, seconds since 1970 (FileBasicInformation; zero times are left alone)."
  (with-handle (fid s path :access #x00100100)          ; WRITE_ATTRIBUTES | SYNCHRONIZE
    (%set-info s fid 4 (cat (le64 0) (le64 0) (le64 (* 10000000 (+ mtime 11644473600))) (le64 0) (le32 0) (le32 0)))))

(defun smb-rename (s from to &key replace)
  "Rename FROM to TO (both from the share's root)."
  (with-handle (fid s from :access +delete-access+)
    (let ((name (utf16le (%smb-path to))))
      (%set-info s fid 10 (cat (octets-of (if replace 1 0) 0 0 0 0 0 0 0) (le64 0) (le32 (length name)) name)))))

(defun smb-statvfs (s)
  "(values TOTAL-BYTES FREE-BYTES) of the share."
  (with-handle (fid s "" :access #x00100081 :options 1)
    (multiple-value-bind (status r)
        (%request s 16 (cat (le16 41) (octets-of 2 7) (le32 64) (le16 0) (le16 0) (le32 0) (le32 0) (le32 0) fid (octets 1)))
      (declare (ignore status))
      (let* ((off (- (u16 r 2) 64)) (unit (* (u32 r (+ off 24)) (u32 r (+ off 28)))))
        (values (* unit (u64 r off)) (* unit (u64 r (+ off 8))))))))
