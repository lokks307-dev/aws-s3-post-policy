package s3post

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/lokks307/go-util/bytesbuilder"
)

type S3PostPolicyParams struct {
	AccessKeyID     string
	AccessKeySecret string
	Region          string
	BucketName      string
}

type S3PostPolicy struct {
	Config     S3PostPolicyParams
	Now        time.Time
	Expiration time.Time
	Conditions map[string]interface{}
}

func NewS3PostPolicy(param ...S3PostPolicyParams) *S3PostPolicy {
	new := S3PostPolicy{}
	if len(param) > 0 {
		new.Config = param[0]
	}
	new.Init()

	return &new
}

func (m *S3PostPolicy) Init() {
	m.Conditions = make(map[string]interface{})
	m.Now = time.Now()
	m.SetPolicyExpire(24)
	if m.Config.BucketName != "" {
		m.SetBucket(m.Config.BucketName)
	}

	if m.Config.AccessKeyID != "" && m.Config.Region != "" {
		m.MakeCredential()
	}
}

func (m *S3PostPolicy) Get(key string) (string, error) {
	if key == "" {
		return "", errors.New("empty key")
	}

	if val, ok := m.Conditions[key]; ok {
		retStr := ""
		switch realVal := val.(type) {
		case []interface{}:
			// TODO:
		default:
			retStr = fmt.Sprintf("%v", realVal)
		}

		return retStr, nil
	} else {
		return "", errors.New("key not found")
	}
}

func (m *S3PostPolicy) MakeCredential() {
	m.setElementValue("x-amz-algorithm", "AWS4-HMAC-SHA256")
	nowStr := m.Now.UTC().Format(TIME_LAYOUT_DATE)
	m.setElementValue("x-amz-date", nowStr)
	cred := strings.Join([]string{m.Config.AccessKeyID, nowStr[0:8], m.Config.Region, "s3", "aws4_request"}, "/")
	m.setElementValue("x-amz-credential", cred)
}

func (m *S3PostPolicy) SetPolicyExpire(hours int) {
	now := time.Now()
	now.Add(time.Hour * time.Duration(hours))
	m.Expiration = now
}

func (m *S3PostPolicy) SetAcl(value string) {
	if value == "" {
		value = ACL_PRIVATE
	}
	m.setElementValue("acl", value)
}

func (m *S3PostPolicy) SetBucket(value string) {
	m.setElementValue("bucket", value)
}

func (m *S3PostPolicy) SetContentLenRange(min, max int) {
	m.Conditions["content-length-range"] = []interface{}{"content-length-range", min, max}
}

func (m *S3PostPolicy) SetRESTHeader(content, value string) {
	switch content {
	case "Cache-Control":
		fallthrough
	case "Content-Type":
		fallthrough
	case "Content-Disposition":
		fallthrough
	case "Content-Encoding":
		fallthrough
	case "Expires":
		m.setElementValue(content, value)
	default:
		return
	}
}

func (m *S3PostPolicy) SetKey(filepath string) {
	m.setElementValue("key", filepath)
}

func (m *S3PostPolicy) SetSuccessActionRedirect(url string) {
	m.setElementValue("success_action_redirect", url)
}

func (m *S3PostPolicy) SetSuccessActionStatus(code string) {
	m.setElementValue("success_action_status", code)
}

func (m *S3PostPolicy) SetUserMetadata(name, value string) {
	m.setElementValue("x-amz-meta-"+name, value)
}

func (m *S3PostPolicy) SetXAmzHeader(name, value string) {
	m.setElementValue("x-amz-"+name, value)
}

func (m *S3PostPolicy) setElementValue(key, value string) {
	m.Conditions[key] = value
}

func (m *S3PostPolicy) SetAclCondition(matchExp, value string) {
	m.setElementCondition(matchExp, "acl", value)
}

func (m *S3PostPolicy) SetRESTHeaderCondition(matchExp, content, value string) {
	switch content {
	case "Cache-Control":
		fallthrough
	case "Content-Type":
		fallthrough
	case "Content-Disposition":
		fallthrough
	case "Content-Encoding":
		fallthrough
	case "Expires":
		m.setElementCondition(matchExp, content, value)
	default:
		return
	}
}

func (m *S3PostPolicy) SetKeyCondition(matchExp, value string) {
	m.setElementCondition(matchExp, "key", value)
}

func (m *S3PostPolicy) SetSuccessActionRedirectCondition(matchExp, value string) {
	m.setElementCondition(matchExp, "success_action_redirect", value)
}

func (m *S3PostPolicy) SetSuccessActionStatusCondition(matchExp, value string) {
	m.setElementCondition(matchExp, "success_action_status", value)
}

func (m *S3PostPolicy) SetUserMetadataCondition(matchExp, name, value string) {
	key := "x-amz-meta-" + name
	m.setElementCondition(matchExp, key, value)
}

func (m *S3PostPolicy) setElementCondition(matchExp, key, value string) {
	m.Conditions[key] = []string{matchExp, "$" + key, value}
}

func (m *S3PostPolicy) GetPolicy() string {
	m.MakeCredential()
	var builder strings.Builder
	builder.WriteString(`{ "expiration": `)
	builder.WriteString(`"` + m.Expiration.UTC().Format(TIME_LAYOUT_EXPIRATION) + `"`)
	builder.WriteString(",\n")
	builder.WriteString("  \"conditions\": [\n")

	for k := range m.Conditions {
		builder.WriteString("    ")
		switch val := m.Conditions[k].(type) {
		case string:
			builder.WriteString(fmt.Sprintf("{%q: %q},\n", k, val))
		case []string:
			str := ""
			for i := range val {
				str += fmt.Sprintf("%q,", val[i])
			}
			str = strings.TrimRight(str, ",")
			builder.WriteString(fmt.Sprintf("[%s],\n", str))
		case []interface{}:
			str := ""
			for i := range val {
				valStr := fmt.Sprintf("%v", val[i])
				if reflect.TypeOf(val[i]).Kind() == reflect.String {
					valStr = fmt.Sprintf("%q", valStr)
				}
				str += valStr
				str += ","
			}
			str = strings.TrimRight(str, ",")
			builder.WriteString(fmt.Sprintf("[%s],\n", str))
		default:
			fmt.Println("key:", k, " type:", reflect.ValueOf(m.Conditions[k]).Type())
		}
	}

	semiPolicy := builder.String()
	semiPolicy = strings.TrimRight(semiPolicy, ", \n\t")
	semiPolicy += "\n  ]\n}"

	return base64.StdEncoding.EncodeToString([]byte(semiPolicy))
}

func (m *S3PostPolicy) MakeSigningKey() []byte {

	bbuilder := bytesbuilder.NewBuilder()
	bbuilder.Append("AWS4", m.Config.AccessKeySecret)
	dateKeyMac := hmac.New(sha256.New, bbuilder.GetBytes())
	dateKeyMac.Write([]byte(m.Now.UTC().Format(TIME_LAYOUT_DATE)[0:8]))
	dateKey := dateKeyMac.Sum(nil)
	bbuilder.Clear()

	regionKeyMac := hmac.New(sha256.New, dateKey)
	regionKeyMac.Write([]byte(m.Config.Region))
	regionKey := regionKeyMac.Sum(nil)

	serviceKeyMac := hmac.New(sha256.New, regionKey)
	serviceKeyMac.Write([]byte("s3"))
	serviceKey := serviceKeyMac.Sum(nil)

	signKeyMac := hmac.New(sha256.New, serviceKey)
	signKeyMac.Write([]byte("aws4_request"))

	return signKeyMac.Sum(nil)
}

func (m *S3PostPolicy) GenerateSignature(policy string, signKey []byte) string {
	h := hmac.New(sha256.New, signKey)
	h.Write([]byte(policy))

	return hex.EncodeToString(h.Sum(nil))
}

func LoadAccessKey(filepath string) ([]string, error) {
	f, _ := os.Open(filepath)
	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}

	return records[1], nil
}
