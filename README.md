# gnark-substring
## Installation
Fallow https://go.dev/doc/install for installation golang.

## Overview
You can use the following commands to run circuit.
```bash
go mod tidy
go mod run
```
This circuit is designed to determine whether one string is a substring of another string.

Lenght of inputs can be specified in this lines
```go
const (
	stringLength    = 10
	substringLenght = 5
)
```

By changing this lines you can change big string
```go
// Secret values
a := make([]*big.Int, stringLength)
inputString := "HELLOWORLD"
for i, char := range inputString {
    if i < stringLength {
        a[i] = big.NewInt(int64(char))
    }
}
```

By editing this line you can change substring
```go
b := make([]*big.Int, regexLength)
regexPattern := "WORLD"
for i, char := range regexPattern {
    if i < regexLength {
        b[i] = big.NewInt(int64(char))
    }
}
````
