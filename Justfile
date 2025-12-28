set shell := ["powershell.exe", "-c"]

test:
    go test -v -cover -coverprofile cover.out ./...

coverage-html:
    go tool cover -html cover.out -o cover.html
