#OTP
## Documentation
```go
package main

import (
    "crypto/sha1"
    "fmt"
    "time"

    "github.com/Luuped/otp"
)

func main() {
    secret := "JBSWY3DPEHPK3PXP"
    totp, err := otp.NewTOTP(secret, 6, sha1.New, "user@example.com", "ExampleIssuer", 30)
    if err != nil {
        fmt.Println("Error creating TOTP:", err)
        return
    }

    otpNow, err := totp.Now()
    if err != nil {
        fmt.Println("Error generating OTP:", err)
        return
    }

    fmt.Println("Current OTP:", otpNow)

    valid := totp.Verify(otpNow, time.Now(), 1)
    fmt.Println("Is OTP valid?", valid)
}
```

## Installation

To install, use the `go get` command:

```sh
go get -u github.com/Luuped/otp
```


## License
This project is licensed under the [MIT License](https://choosealicense.com/licenses/mit/).