;;;; package.lisp

(defpackage #:cl-smb
  (:use #:cl)
  (:nicknames #:smb)
  (:export
   ;; a session on one share
   #:smb-connect #:smb-disconnect #:smb-session #:smb-session-p #:smb-session-share #:smb-session-dialect
   #:smb-session-signing-p
   ;; what is there
   #:smb-entry #:smb-entry-name #:smb-entry-directory-p #:smb-entry-size #:smb-entry-mtime
   #:smb-entry-attributes #:smb-list #:smb-map-entries #:smb-stat #:smb-statvfs
   ;; reading and writing
   #:smb-read-range #:smb-get #:smb-put #:smb-write-range #:smb-read-file
   #:smb-map-file #:smb-open-write #:smb-write #:smb-finish-write #:smb-abandon-write #:*smb-ahead*
   ;; changing it
   #:smb-mkdir #:smb-rmdir #:smb-delete #:smb-rename #:smb-set-mtime
   ;; when it goes wrong
   #:smb-error #:smb-error-status #:smb-error-message #:smb-auth-error
   #:*wait-hook*))
