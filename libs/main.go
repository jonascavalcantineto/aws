package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudtrail"
)

func main() {

	type FailureEventRunTask struct {
		ARN    string `json:"arn"`
		Reason string `json:"reason"`
	}

	type TrailEventInfo struct {
		EventVersion string                 `json:"eventVersion"`
		UserIdentity map[string]interface{} `json:"userIdentity"`
		EventTime    string                 `json:"eventTime"`
		Failures     []FailureEventRunTask  `json:"failure"`
	}

	sess, err := session.NewSession()
	svc := cloudtrail.New(sess)
	//svc2 := cloudtrailclient.New(sess)

	maxResults := int64(1)

	input := &cloudtrail.LookupEventsInput{
		StartTime: aws.Time(time.Now().Add(-12 * time.Hour).UTC()),
		EndTime:   aws.Time(time.Now().UTC()),
		LookupAttributes: []*cloudtrail.LookupAttribute{
			{
				AttributeKey:   aws.String("EventName"),
				AttributeValue: aws.String("RunTask"),
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

	// failuremok := `{"failure":[
	// 	{"arn":"arn ecs:sa-east-1:360706934225:container-instance/0d9db362011747d389606f4e5496af6f","reason":"RESOURCE:CPU"},
	// 	{"arn":"arn ecs:sa-east-1:360706934225:container-instance/2503789574374dc691f2dc6b7230a4cd","reason":"RESOURCE:CPU"}
	// ]}`
	//failuremok := `{"failure":[]}`

	for _, event := range resp.Events {

		var trailEventInfo TrailEventInfo

		json.Unmarshal([]byte(aws.StringValue(event.CloudTrailEvent)), &trailEventInfo)

		//json.Unmarshal([]byte(aws.StringValue(&failuremok)), &trailEventInfo)

		fmt.Println("Event: ")
		fmt.Println("Name    ", aws.StringValue(event.EventName))
		fmt.Println("Version: ", trailEventInfo.EventVersion)
		fmt.Println("Time: ", trailEventInfo.EventTime)

		if len(trailEventInfo.Failures) <= 0 {
			fmt.Println("No Failures")
		} else {
			var payload string
			payload = "{\"text\": \" [CLOUDTRAIL - RUNTASK] DEFCON 5: "
			payload += trailEventInfo.Failures[0].Reason + "\","
			payload += "\"channel\":\" #ec_casterlyrock_hmg\", \"icon_emoji\":\":computer:\"}"

			url := "https://hooks.slack.com/services/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"

			sendMessageToSlack(url, payload)
		}

	}

}

func sendMessageToSlack(url string, paylod string) {

	req, _ := http.NewRequest("POST", url, strings.NewReader(paylod))

	req.Header.Add("content-type", "application/json")

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Println("Error send message to Slack")
		fmt.Println(err.Error())
		os.Exit(1)
	}

	defer res.Body.Close()

	body, _ := ioutil.ReadAll(res.Body)

	fmt.Println(string(body))
}
