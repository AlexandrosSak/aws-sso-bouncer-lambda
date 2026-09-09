package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

// Request represents your input request
type Request struct {
	QueryStringParameters map[string]string `json:"queryStringParameters"`
	Headers               map[string]string `json:"headers"`
	Path                  string            `json:"path"`
}

type RequestHeaders struct {
	Accept          string `json:"accept"`
	AcceptLanguage  string `json:"accept-language"`
	ContentType     string `json:"Content-Type"`
	Cookie          string `json:"cookie"`
	Host            string `json:"host"`
	UserAgent       string `json:"user-agent"`
	XAmznTraceId    string `json:"x-amzn-trace-id"`
	XForwardedFor   string `json:"x-forwarded-for"`
	XForwardedPort  string `json:"x-forwarded-port"`
	XForwardedProto string `json:"x-forwarded-proto"`
}

// Response represents your output response
type Response struct {
	IsBase64Encoded   bool              `json:"isBase64Encoded"`
	StatusCode        int               `json:"statusCode"`
	StatusDescription string            `json:"statusDescription"`
	Headers           map[string]string `json:"headers"`
	Body              string            `json:"body"`
}

var (
	awsRegion       = os.Getenv("BOUNCER_REGION")
	securityGroupID = os.Getenv("BOUNCER_SECURITY_GROUP_ID")
	accountName     = os.Getenv("ACCOUNT_NAME")
)

func allowUserIP(userIP string) error {
	// Create an AWS session using the provided credentials
	awsSession := session.Must(session.NewSession(&aws.Config{
		Region: aws.String(awsRegion),
	}))

	// Create an EC2 service client
	ec2Client := ec2.New(awsSession)

	// Describe the existing rules for the security group
	describeRulesInput := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{aws.String(securityGroupID)},
	}

	describeRulesOutput, err := ec2Client.DescribeSecurityGroups(describeRulesInput)
	if err != nil {
		log.Printf("Error describing security group rules: %v", err)
		return err
	}

	// Check if the user's IP is already in the authorized IP ranges
	for _, ipPermission := range describeRulesOutput.SecurityGroups[0].IpPermissions {
		for _, ipRange := range ipPermission.IpRanges {
			if *ipRange.CidrIp == fmt.Sprintf("%s/32", userIP) {
				// User's IP is already authorized
				return fmt.Errorf("user's IP %s is already in the allowed list", userIP)
			}
		}
	}

	// If the loop completes without returning, it means the user's IP is not yet authorized

	// Modify Security Group rules to allow incoming traffic from the user's IP
	log.Printf("Before AuthorizeSecurityGroupIngress - User IP: %s", userIP)
	_, err = ec2Client.AuthorizeSecurityGroupIngress(&ec2.AuthorizeSecurityGroupIngressInput{
		GroupId: aws.String(securityGroupID),
		IpPermissions: []*ec2.IpPermission{
			{
				IpProtocol: aws.String("-1"),
				FromPort:   aws.Int64(-1),
				ToPort:     aws.Int64(-1),
				IpRanges: []*ec2.IpRange{
					{
						CidrIp: aws.String(fmt.Sprintf("%s/32", userIP)), // Assuming userIP is a single IP address
					},
				},
			},
		},
	})
	if err != nil {
		log.Printf("Error Authorizing Security Group Ingress: %v", err)
		return err
	}

	log.Printf("After AuthorizeSecurityGroupIngress - User IP: %s", userIP)

	return nil
}

func handler(ctx context.Context, request Request) (Response, error) {
	log.Printf("Start of handler function")
	log.Printf("Received request: %+v", request)
	log.Printf("Security Group ID: %s", securityGroupID)

	userIP := request.Headers["x-forwarded-for"] // Extract user's public IP from headers

	if userIP == "" {
		response := Response{
			IsBase64Encoded:   false,
			StatusCode:        http.StatusBadRequest,
			StatusDescription: "Bad Request",
			Headers: map[string]string{
				"Content-Type":                "text/html",
				"Content-Disposition":         "inline",
				"Access-Control-Allow-Origin": "*",
				"Accept":                      "text/html,application/xhtml+xml",
			},
			Body: "Bad Request: User IP not provided",
		}
		return response, nil
	}

	err := allowUserIP(userIP)
	if err != nil {
		// Check if the error indicates that the IP is already authorized
		if fmt.Sprintf("%v", err) == fmt.Sprintf("user's IP %s is already in the allowed list", userIP) {
			response := Response{
				IsBase64Encoded:   false,
				StatusCode:        http.StatusOK,
				StatusDescription: "200 OK",
				Headers: map[string]string{
					"Content-Type": "text/html",
				},
				Body: "User's IP is already in the allowed list",
			}

			log.Printf("Handler - Successful response: %+v", response)
			log.Printf("End of handler function")

			return response, nil
		}

		// If it's a different error, construct and return an error response
		log.Printf("Error allowing user's IP: %v", err)
		response := Response{
			IsBase64Encoded:   false,
			StatusCode:        http.StatusInternalServerError,
			StatusDescription: "Internal Server Error",
			Headers: map[string]string{
				"Content-Type":                "text/html",
				"Content-Disposition":         "inline",
				"Access-Control-Allow-Origin": "*",
				"Accept":                      "text/html,application/xhtml+xml",
			},
			Body: "Internal Server Error: Failed to allow user's IP through AWS Security Group",
		}

		log.Printf("Handler - Error response: %+v", response)
		log.Printf("End of handler function")

		return response, err
	}

	// Success response after allowing the user's IP
	response := Response{
		IsBase64Encoded:   false,
		StatusCode:        http.StatusOK,
		StatusDescription: "200 OK",
		Headers: map[string]string{
			"Content-Type":                "text/html",
			"Content-Disposition":         "inline",
			"Access-Control-Allow-Origin": "*",
			"Accept":                      "text/html,application/xhtml+xml",
		},
		Body: fmt.Sprintf("<div style='font-size: 20px;'>User's IP added to the allowlist. Account Name: <strong style='background-color: red; color: white; padding: 2px;'>%s</strong></div>", accountName),
	}

	log.Printf("Handler - Successful response: %+v", response)
	log.Printf("End of handler function")

	return response, nil
}

func main() {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Recovered in main: %v", r)
		}
	}()

	lambda.Start(handler)
}
