.PHONY: build deploy

build:
	cd lambda/update && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main bouncer-update.go && zip package.zip main && rm main
	cd lambda/clear && GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o main bouncer-clear.go && zip package.zip main && rm main

deploy:
	aws lambda update-function-code --function-name bouncer-update --zip-file fileb://lambda/update/package.zip --region $(AWS_REGION)
	aws lambda update-function-code --function-name bouncer-clear --zip-file fileb://lambda/clear/package.zip --region $(AWS_REGION)