# cl-smb

An SMB 2/3 client in portable Common Lisp: file shares on Samba, a Mac's File Sharing, NAS boxes and
Windows. Written from Microsoft's published protocol documents (MS-SMB2, MS-NLMP), with no FFI.

- **Dialects** 2.0.2, 2.1, 3.0 and 3.0.2.
- **Logon** with an NTLMv2 password, inside SPNEGO.
- **Signing** of every request after logon, and every reply checked: HMAC-SHA256 for 2.x, AES-CMAC with
  the SP 800-108 derived key from 3.0.
- **Files**: list, stat, read (a range, or a whole file streamed), write (a range, or a whole file),
  mkdir, rmdir, delete, rename, set a file's time, and the share's size and free space.

Crypto comes from [natrium](https://github.com/modus-lisp/natrium). The only platform dependency is
SBCL's `sb-bsd-sockets`, which [modus](https://github.com/modus-lisp/modus) provides too.

```lisp
(let ((s (smb:smb-connect "nas.local" :user "me" :password "…" :share "Public")))
  (dolist (e (smb:smb-list s "/docs"))
    (format t "~a~:[~;/~] ~d~%" (smb:smb-entry-name e) (smb:smb-entry-directory-p e) (smb:smb-entry-size e)))
  (smb:smb-get s "/docs/report.pdf" "/tmp/report.pdf")
  (smb:smb-disconnect s))
```

Not yet: SMB 3.1.1 (preauthentication integrity), encryption (a share that requires it is refused with
a clear error), Kerberos, and listing a server's shares.

## Testing

`sbcl --script test/core.lisp` runs every check at 3.0.2 and again at 2.1, against a Samba that requires
signing, on 127.0.0.1:4450: user `cl-smb`, password `hunter2`, share `Public` (`SMB_HOST`, `SMB_PORT`,
`SMB_USER` and `SMB_PASSWORD` say otherwise):

```
docker run -d --name cl-smb-samba -p 4450:445 alpine:3.20 sh -c '
  apk add --no-cache samba >/dev/null &&
  (id cl-smb >/dev/null 2>&1 || adduser -D cl-smb) && (echo hunter2; echo hunter2) | smbpasswd -s -a cl-smb &&
  mkdir -p /srv/public/docs && echo hello > /srv/public/docs/hello.txt &&
  dd if=/dev/urandom of=/srv/public/docs/big.bin bs=1M count=3 2>/dev/null && chown -R cl-smb /srv/public &&
  printf "[global]\n server min protocol = SMB2_02\n server max protocol = SMB3\n server signing = mandatory\n map to guest = never\n[Public]\n path = /srv/public\n read only = no\n valid users = cl-smb\n" > /etc/samba/smb.conf &&
  exec smbd --foreground --no-process-group --debug-stdout'
```

MIT.
