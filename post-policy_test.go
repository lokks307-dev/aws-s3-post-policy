package main

import (
	"fmt"
	"testing"
	"time"
)

var acsKeyID = "AKIAIOSFODNN7EXAMPLE"
var acsKeySecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
var OriginalPolicy = "eyAiZXhwaXJhdGlvbiI6ICIyMDE1LTEyLTMwVDEyOjAwOjAwLjAwMFoiLA0KICAiY29uZGl0aW9ucyI6IFsNCiAgICB7ImJ1Y2tldCI6ICJzaWd2NGV4YW1wbGVidWNrZXQifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRrZXkiLCAidXNlci91c2VyMS8iXSwNCiAgICB7ImFjbCI6ICJwdWJsaWMtcmVhZCJ9LA0KICAgIHsic3VjY2Vzc19hY3Rpb25fcmVkaXJlY3QiOiAiaHR0cDovL3NpZ3Y0ZXhhbXBsZWJ1Y2tldC5zMy5hbWF6b25hd3MuY29tL3N1Y2Nlc3NmdWxfdXBsb2FkLmh0bWwifSwNCiAgICBbInN0YXJ0cy13aXRoIiwgIiRDb250ZW50LVR5cGUiLCAiaW1hZ2UvIl0sDQogICAgeyJ4LWFtei1tZXRhLXV1aWQiOiAiMTQzNjUxMjM2NTEyNzQifSwNCiAgICB7IngtYW16LXNlcnZlci1zaWRlLWVuY3J5cHRpb24iOiAiQUVTMjU2In0sDQogICAgWyJzdGFydHMtd2l0aCIsICIkeC1hbXotbWV0YS10YWciLCAiIl0sDQoNCiAgICB7IngtYW16LWNyZWRlbnRpYWwiOiAiQUtJQUlPU0ZPRE5ON0VYQU1QTEUvMjAxNTEyMjkvdXMtZWFzdC0xL3MzL2F3czRfcmVxdWVzdCJ9LA0KICAgIHsieC1hbXotYWxnb3JpdGhtIjogIkFXUzQtSE1BQy1TSEEyNTYifSwNCiAgICB7IngtYW16LWRhdGUiOiAiMjAxNTEyMjlUMDAwMDAwWiIgfQ0KICBdDQp9"
var OriginalSig = "8afdbf4008c03f22c2cd3cdb72e4afbb1f6a588f3255ac628749a66d7f09699e"

var Bucket = "sigv4examplebucket"
var BucketRegion = "us-east-1"

func TestAwsSample(t *testing.T) {
	param := S3PostPolicyParams{
		AccessKeyID:     acsKeyID,
		AccessKeySecret: acsKeySecret,
		Region:          BucketRegion,
		BucketName:      Bucket,
	}

	policy := NewS3PostPolicy(param)
	policy.Now = time.Unix(1451347200, 0)
	policy.Expiration = time.Unix(1451476800, 0)
	policy.MakeCredential()

	policy.SetBucket(Bucket)
	policy.SetKeyCondition(EXP_STARTS_WITH, "user/user1/")
	policy.SetAcl(ACL_PUBLIC_READ)
	policy.SetSuccessActionRedirect("http://sigv4examplebucket.s3.amazonaws.com/successful_upload.html")
	policy.SetRESTHeaderCondition(EXP_STARTS_WITH, "Content-Type", "image/")
	policy.SetUserMetadata("uuid", "14365123651274")
	policy.SetXAmzHeader("server-side-encryption", "AES256")
	policy.SetUserMetadataCondition(EXP_STARTS_WITH, "tag", "")

	fmt.Println(policy.GetPolicy())

	signKey := policy.MakeSigningKey()
	sig := policy.GenerateSignature(OriginalPolicy, signKey)

	if sig == OriginalSig {
		fmt.Println(true)
	} else {
		fmt.Println(sig)
	}
}

func TestAccess(t *testing.T) {
	LoadAccessKey("C:/shared/cathy_accessKeys.csv")
}
