# KWallet-PAM

## How kwallet-pam works:

During the pam "auth" (pam_authenticate) stage the module gets the password in plain text.
It hashes it against a random salt previously generated by kwallet of random data and keeps it in memory.

When we get to the "session" (pam_open_session) stage the pam module forks and launches kwalletd as the user with file descriptor AND a socket.
We send the salted password over the file descriptor after forking and write the socket address to an env variable.

KWalletd recieves the pre-hashed key and then sits there doing nothing. (before the QApplication constructor)

Later after session startup (autostart apps phase 0) a small script passes the newly set environment from the user session to kwalletd over the socket.

kwalletd receives this, sets the environment variables and continues into the normal bootup.

The session env is needed as if we launch pre session various important env vars are not set and kwalletd is a graphical app.

## Setup

```sh
apt install libpam-kwallet5 
```
