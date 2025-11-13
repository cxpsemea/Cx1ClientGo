module github.com/cxpsemea/Cx1ClientGo/examples/OneHundredApps

go 1.23.0

toolchain go1.23.3

require (
	github.com/cxpsemea/Cx1ClientGo v0.1.35
	github.com/sirupsen/logrus v1.9.3
	github.com/t-tomalak/logrus-easy-formatter v0.0.0-20190827215021-c074f06c5816
)

require (
	github.com/golang-jwt/jwt/v4 v4.5.2 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	golang.org/x/exp v0.0.0-20250408133849-7e4ce0ab07d0 // indirect
	golang.org/x/sys v0.27.0 // indirect
)

replace github.com/cxpsemea/Cx1ClientGo v0.1.35 => ../../
