package s3post

const (
	ACL_PRIVATE            = "private"
	ACL_PUBLIC_READ        = "public-read"
	ACL_PUBLIC_READ_WRITE  = "public-read-write"
	ACL_AWS_EXEC_READ      = "aws-exec-read"
	ACL_AUTH_READ          = "authenticated-read"
	ACL_BUCKET_OWNER_READ  = "bucket-owner-read"
	ACL_BUCKET_OWNER_FULL  = "bucket-owner-full-control"
	ACL_LOG_DELIVERY_WRITE = "log-delivery-write"
)

const (
	EXP_EXACT       = "eq"
	EXP_STARTS_WITH = "starts-with"
)

const (
	TIME_LAYOUT_EXPIRATION = "2006-01-02T15:04:05.000Z"
	TIME_LAYOUT_DATE       = "20060102T150405Z"
)
