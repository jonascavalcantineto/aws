package cloudtrailclient

import (
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

//New (sess *session.Session) *cloudtrail.CloudTrail
//Creating a new Cloudtrail service
func New(sess *session.Session) *cloudtrail.CloudTrail {
	return cloudtrail.New(sess)
}
