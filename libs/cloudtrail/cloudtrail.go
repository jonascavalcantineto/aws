package cloudtrail

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

func CloudTrailNew(sess *session.Session) *cloudtrail.CloudTrail {
	return cloudtrail.New(sess)
}
