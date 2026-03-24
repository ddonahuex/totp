# totp Program
Generates a Time-Based One-Time Password (TOTP) based on a Base32-encoded secret
and appends it to a given password.

## Reference Code
Code is for reference only. Will exit with error for invalid Base32 secret value.

## Build and run

### Go
To build:
```
  $ go build -o totp-generator ./cmd/go
```

To run:
The Go executable supports providing the password and 2FA secret via either
environment variables or command-line flags.

#### Environment Variables
```
  $ export HV_PASSWORD="somepassword"
  $ export HV_SECRET="abcdefghijklmnopqrstuvwxyz"
  $ ./totp-generator
  Generated TOTP: 418926
  SFTP Password:  somepassword418926
```
#### Command Line Flags
```
  ddonahue@ubuntu-svr$ ./totp-generator --secret="abcdefghi" --pass="password"
  Generated TOTP: 399974
  SFTP Password:  password399974
```

### Javascript
To run:
```
  $ node totp.js 
```

Example output:
```
  Generated TOTP: 569634
  SFTP Password:  password569634
```
