;;;; ntlm.lisp -- NTLMv2 logon (MS-NLMP), inside SPNEGO (RFC 4178), as SMB2 SESSION_SETUP carries it.
;;;;
;;;; Three messages: our NEGOTIATE, the server's CHALLENGE, our AUTHENTICATE.  No key exchange
;;;; (NTLMSSP_NEGOTIATE_KEY_EXCH is not asked for), so the session key is NTLMv2's SessionBaseKey and
;;;; no RC4 is needed; no MIC (MsvAvFlags is not set), so neither is the NTLM signing of the SPNEGO
;;;; mechList.  Samba and a Mac's File Sharing accept that.

(in-package #:cl-smb)

(defconstant +ntlm-flags+
  (logior #x00000001     ; NEGOTIATE_UNICODE
          #x00000004     ; REQUEST_TARGET
          #x00000010     ; NEGOTIATE_SIGN
          #x00000200     ; NEGOTIATE_NTLM
          #x00008000     ; NEGOTIATE_ALWAYS_SIGN
          #x00080000     ; NEGOTIATE_EXTENDED_SESSIONSECURITY
          #x00800000     ; NEGOTIATE_TARGET_INFO
          #x20000000))   ; NEGOTIATE_128

(defparameter +ntlmssp+ (ascii (format nil "NTLMSSP~c" (code-char 0))))
(defparameter +spnego-oid+ (octets-of #x2b #x06 #x01 #x05 #x05 #x02))                     ; 1.3.6.1.5.5.2
(defparameter +ntlm-oid+ (octets-of #x2b #x06 #x01 #x04 #x01 #x82 #x37 #x02 #x02 #x0a))  ; 1.3.6.1.4.1.311.2.2.10

(defun ntlm-negotiate ()
  "The NTLMSSP NEGOTIATE_MESSAGE: no domain or workstation supplied."
  (cat +ntlmssp+ (le32 1) (le32 +ntlm-flags+) (octets 8) (octets 8)))

(defun spnego-init (ntlm)
  "NegTokenInit offering NTLMSSP, with its first token."
  (der #x60
       (der #x06 +spnego-oid+)
       (der #xa0 (der #x30
                      (der #xa0 (der #x30 (der #x06 +ntlm-oid+)))
                      (der #xa2 (der #x04 ntlm))))))

(defun spnego-response (ntlm)
  "NegTokenResp carrying our next token."
  (der #xa1 (der #x30 (der #xa2 (der #x04 ntlm)))))

(defun spnego-token (blob)
  "The mechanism token in the server's SPNEGO BLOB (NegTokenResp, or a bare NTLMSSP message), or NIL."
  (cond ((and (>= (length blob) 8) (equalp (subseq blob 0 8) +ntlmssp+)) blob)
        ((zerop (length blob)) nil)
        (t (let ((at (der-find blob 0 (length blob) #xa1 #x30 #xa2 #x04)))
             (and at (subseq blob (first at) (second at)))))))

(defun spnego-accepted-p (blob)
  "Does the server's final NegTokenResp say accept-completed (or say nothing at all)?"
  (let ((at (and (plusp (length blob)) (der-find blob 0 (length blob) #xa1 #x30 #xa0 #x0a))))
    (or (null at) (zerop (aref blob (first at))))))

(defun %ntlm-field (msg off)
  "The bytes of the (LEN MAXLEN OFFSET) field at OFF in an NTLMSSP message."
  (let ((len (u16 msg off)) (at (u32 msg (+ off 4))))
    (subseq msg at (+ at len))))

(defun parse-challenge (msg)
  "(values SERVER-CHALLENGE TARGET-INFO FLAGS) from an NTLMSSP CHALLENGE_MESSAGE."
  (unless (and (>= (length msg) 48) (equalp (subseq msg 0 8) +ntlmssp+) (= (u32 msg 8) 2))
    (error 'smb-auth-error :status 0 :message "the server's logon challenge was not NTLMSSP"))
  (values (subseq msg 24 32) (%ntlm-field msg 40) (u32 msg 20)))

(defun av-pair (info id)
  "The value of AV_PAIR ID in the TARGET-INFO list, or NIL."
  (loop with i = 0
        while (<= (+ i 4) (length info))
        do (let ((av (u16 info i)) (len (u16 info (+ i 2))))
             (when (zerop av) (return nil))
             (when (= av id) (return (subseq info (+ i 4) (+ i 4 len))))
             (incf i (+ 4 len)))))

(defun filetime-now ()
  "Now, as a Windows FILETIME: 100 ns since 1601."
  (* 10000000 (+ (- (get-universal-time) (encode-universal-time 0 0 0 1 1 1970 0)) 11644473600)))

(defun ntlm-authenticate (user password domain challenge-msg)
  "(values AUTHENTICATE-MESSAGE SESSION-KEY) for USER/PASSWORD in DOMAIN answering CHALLENGE-MSG."
  (multiple-value-bind (server-challenge target-info) (parse-challenge challenge-msg)
    (let* ((nt-hash (natrium:md4 (utf16le password)))
           (response-key (natrium:hmac-md5 nt-hash (utf16le (concatenate 'string (string-upcase user) domain))))
           (client-challenge (natrium:random-bytes 8))
           (stamp (or (av-pair target-info 7) (le64 (filetime-now))))
           (temp (cat (octets-of 1 1 0 0 0 0 0 0) stamp client-challenge (octets 4) target-info (octets 4)))
           (proof (natrium:hmac-md5 response-key (cat server-challenge temp)))
           (nt-response (cat proof temp))
           ;; a server that sends a timestamp wants the LM response zeroed (MS-NLMP 3.3.2)
           (lm-response (if (av-pair target-info 7)
                            (octets 24)
                            (cat (natrium:hmac-md5 response-key (cat server-challenge client-challenge))
                                 client-challenge)))
           (session-key (natrium:hmac-md5 response-key proof))
           (dom (utf16le domain)) (usr (utf16le user)) (ws (utf16le ""))
           (payload-start 88)
           (fields '()) (payload '()) (at payload-start))
      (flet ((field (bytes)
               (push (cat (le16 (length bytes)) (le16 (length bytes)) (le32 at)) fields)
               (push bytes payload)
               (incf at (length bytes))))
        (field lm-response) (field nt-response) (field dom) (field usr) (field ws) (field (octets 0)))
      (values (apply #'cat +ntlmssp+ (le32 3)
                     (append (reverse fields)
                             (list (le32 +ntlm-flags+) (octets 8) (octets 16))  ; flags, version, MIC (unused)
                             (reverse payload)))
              session-key))))
