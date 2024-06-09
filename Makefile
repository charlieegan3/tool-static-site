FILE_PATTERN := 'yaml\|html\|go\|sql\|Makefile\|js\|csg'
dev_server:
	find . | grep $(FILE_PATTERN) | GO_ENV=dev entr -c -r go run cmd/tool/main.go
