build:
	go build -o bin/main read_pe.go

run:
	go run read_pe.go
	
compile:
	# Linux
	GOOS=linux GOARCH=amd64 go build -o bin/lin_read_pe read_pe.go
	# Windows
	GOOS=windows GOARCH=amd64 go build -o bin/win_read_pe.exe read_pe.go

