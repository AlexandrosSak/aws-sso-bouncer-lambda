package main

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
)

func clearSecurityGroup(ctx context.Context, event events.CloudWatchEvent) error {
	// Get AWS region from environment variable
	region := os.Getenv("BOUNCER_REGION")
	if region == "" {
		region = "eu-west-1" // Default region if not set
	}

	// AWS session configuration
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String(region),
	})
	if err != nil {
		return err
	}

	// Create an EC2 service client
	svc := ec2.New(sess)

	// Get Security Group ID from environment variable
	securityGroupID := os.Getenv("BOUNCER_SECURITY_GROUP_ID")
	if securityGroupID == "" {
		return fmt.Errorf("BOUNCER_SECURITY_GROUP_ID environment variable not set")
	}

	// Specify the rules to keep
	keepRules := []*ec2.IpPermission{
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(443),
			ToPort:     aws.Int64(443),
			IpRanges: []*ec2.IpRange{
				{CidrIp: aws.String("0.0.0.0/0")},
			},
		},
		{
			IpProtocol: aws.String("tcp"),
			FromPort:   aws.Int64(80),
			ToPort:     aws.Int64(80),
			IpRanges: []*ec2.IpRange{
				{CidrIp: aws.String("0.0.0.0/0")},
			},
		},
		{
			IpProtocol: aws.String("icmp"),
			FromPort:   aws.Int64(-1),
			ToPort:     aws.Int64(-1),
			Ipv6Ranges: []*ec2.Ipv6Range{
				{CidrIpv6: aws.String("::/0")},
			},
		},
		{
			IpProtocol: aws.String("icmp"),
			FromPort:   aws.Int64(-1),
			ToPort:     aws.Int64(-1),
			IpRanges: []*ec2.IpRange{
				{CidrIp: aws.String("0.0.0.0/0")},
			},
		},
	}

	// Describe current security group rules
	describeInput := &ec2.DescribeSecurityGroupsInput{
		GroupIds: []*string{&securityGroupID},
	}

	describeOutput, err := svc.DescribeSecurityGroups(describeInput)
	if err != nil {
		return err
	}

	// Extract existing ingress rules
	existingRules := describeOutput.SecurityGroups[0].IpPermissions

	// Remove rules that should NOT be kept
	fmt.Println("Existing Security Group Rules:")
	for _, rule := range existingRules {
		match := false
		for _, keepRule := range keepRules {
			if aws.StringValue(rule.IpProtocol) == aws.StringValue(keepRule.IpProtocol) &&
				aws.Int64Value(rule.FromPort) == aws.Int64Value(keepRule.FromPort) &&
				aws.Int64Value(rule.ToPort) == aws.Int64Value(keepRule.ToPort) {
				match = true
				break
			}
		}

		if !match {
			// Rule doesn't match any of the keepRules, remove it
			input := &ec2.RevokeSecurityGroupIngressInput{
				GroupId:       aws.String(securityGroupID),
				IpPermissions: []*ec2.IpPermission{rule},
			}

			// Revoke the ingress rule
			_, err := svc.RevokeSecurityGroupIngress(input)
			fmt.Printf("Error revoking rule: %v\n", err)
			if err != nil {
				return err
			}
		}
	}

	fmt.Println("Security group rules cleared successfully")

	return nil
}

func main() {
	// Use the Lambda handler to run the function
	lambda.Start(clearSecurityGroup)
}
