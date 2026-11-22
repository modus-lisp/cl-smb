;;;; cl-smb.asd -- an SMB 2/3 client in portable Common Lisp.

(asdf:defsystem :cl-smb
  :description "An SMB 2/3 client (file shares: Samba, a Mac's File Sharing, NAS boxes) in portable Common
Lisp, written from Microsoft's published MS-SMB2 and MS-NLMP: dialects 2.0.2 to 3.0.2, NTLMv2 password
logon inside SPNEGO, message signing (HMAC-SHA256, and AES-CMAC from 3.0), and the file operations a
file manager needs.  Crypto from natrium; the only platform dependency is SBCL's sb-bsd-sockets (modus
provides it too)."
  :version "0.1.0"
  :author "ynniv"
  :license "MIT"
  :depends-on ("natrium")
  :serial t
  :components ((:module "src" :serial t
                :components ((:file "package") (:file "wire") (:file "ntlm") (:file "client")))))
