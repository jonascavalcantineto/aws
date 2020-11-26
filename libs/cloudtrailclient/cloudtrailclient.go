package cloudtrailclient

import (
	"fmt"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

//New (sess *session.Session) *cloudtrail.CloudTrail
//Creating a new Cloudtrail service
func New(sess *session.Session) *cloudtrail.CloudTrail {
	return cloudtrail.New(sess)
}

//LookupEventsByAttributs (svc *cloudtrail.CloudTrail, attributeKey string, attributeValue string, startTime time.Time, endTime time.Time, maxResults int64) (*cloudtrail.LookupEventsOutput, error)
func LookupEventsByAttributs(svc *cloudtrail.CloudTrail, attributeKey string, attributeValue string, startTime time.Time, endTime time.Time, maxResults int64) (*cloudtrail.LookupEventsOutput, error) {

	input := &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(time.Now().Add(-12 * time.Hour).UTC()),
		EndTime:   aws.Time(time.Now().UTC()),
		LookupAttributes: []*cloudtrail.LookupAttribute{
			{
				AttributeKey:   aws.String(attributeKey),
				AttributeValue: aws.String(attributeValue),
			},
		},
		MaxResults: &maxResults,
	}

	resp, err := svc.LookupEvents(input)
	if err != nil {
		fmt.Println("Got error calling Trails:")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	return resp, err

}
