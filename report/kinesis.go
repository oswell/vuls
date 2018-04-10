/* Vuls - Vulnerability Scanner
Copyright (C) 2018  Future Architect, Inc. Japan.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package report

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/kinesis"
	"github.com/pkg/errors"

	"github.com/future-architect/vuls/config"
	"github.com/future-architect/vuls/models"
	"github.com/future-architect/vuls/util"
)

// KinesisWriter send report to Kinesis
type KinesisWriter struct{}

// KinesisMessage is the data sent as JSON to Kinesis
type KinesisMessage map[string]interface{}

// JSON sent to kinesis is defined as a map with the following keys.
// This is created as a map instead of a struct so that we can append
// custom attributes from the configuration into each object
const (
	KeyTime       = "time"
	KeyServerName = "server_name"
	KeyOSFamily   = "os_family"
	KeyOSRelease  = "os_release"
	KeyIPv4Addrs  = "ipv4_addrs"
	KeyIPv6Addrs  = "ipv6_addrs"
	KeyPackages   = "packages"
	KeyCVEID      = "cve_id"
	KeySeverity   = "severity"
	KeyCVSSScore  = "cvss_score_v2"
	KeyCVSSVector = "cvss_vector_v2"
	KeyCWEID      = "cwe_id"
	KeySourceLink = "source_link"
	KeySummary    = "summary"
)

// Message is a raw JSON string describing a VULS message to be sent to Kinesis
type Message []byte

func (k KinesisWriter) Write(rs ...models.ScanResult) (err error) {
	conf := config.Conf
	sess := session.New(&aws.Config{
		Region: aws.String(conf.AwsRegion),
		Credentials: credentials.NewSharedCredentials(
			conf.AwsCredentialFile,
			conf.AwsProfile,
		),
	})

	kc := kinesis.New(sess)
	streamName := aws.String(conf.Kinesis.Stream)

	if err != nil {
		return errors.Wrap(err, "Failed to initialize kinesis client")
	}

	// Each PutRecords() call handles up to 500 records.  Create a list of entries, each of which can hold
	// up to the 500 records.
	recordList := [][]*kinesis.PutRecordsRequestEntry{}
	records := []*kinesis.PutRecordsRequestEntry{}

	for _, r := range rs {

		messages, err := k.encode(r)
		if err != nil {
			return errors.Wrap(err, "Failed to encode scan results")
		}
		for _, msg := range messages {
			record := kinesis.PutRecordsRequestEntry{
				Data:         msg,
				PartitionKey: aws.String("key"),
			}
			records = append(records, &record)

			if len(records) == 500 {
				recordList = append(recordList, records)
				records = []*kinesis.PutRecordsRequestEntry{}
			}
		}
	}

	recordList = append(recordList, records)

	for _, records := range recordList {
		util.Log.Info(fmt.Sprintf("Putting %d items into kinesis", len(records)))
		input := &kinesis.PutRecordsInput{
			Records:    records,
			StreamName: streamName,
		}
		_, err = kc.PutRecords(input)
		if err != nil {
			return errors.Wrap(err, "Failed to write records to kinesis")
		}
	}

	return nil
}

func (k KinesisWriter) encode(result models.ScanResult) ([]Message, error) {
	messages := make([]Message, 0)
	for cveID, vinfo := range result.ScannedCves {
		message := KinesisMessage{}

		message[KeyTime] = result.ScannedAt
		message[KeyServerName] = result.ServerName

		if config.Conf.Kinesis.ForceHostname {
			hostname, err := os.Hostname()

			// If an error occurs getting the hostname, then continue on as-is,
			// otherwise set the value
			if err == nil {
				message[KeyServerName] = hostname
			}
		}

		message[KeyOSFamily] = result.Family
		message[KeyOSRelease] = result.Release
		message[KeyIPv4Addrs] = result.IPv4Addrs
		message[KeyIPv6Addrs] = result.IPv6Addrs

		var pkgNames []string
		for _, pkg := range vinfo.AffectedPackages {
			pkgNames = append(pkgNames, pkg.Name)
		}
		message[KeyPackages] = pkgNames
		message[KeyCVEID] = cveID

		for _, cvss := range vinfo.Cvss2Scores() {
			if cvss.Type != models.NVD {
				continue
			}
			message[KeySeverity] = cvss.Value.Severity
			message[KeyCVSSScore] = cvss.Value.Score
			message[KeyCVSSVector] = cvss.Value.Vector
		}

		if content, ok := vinfo.CveContents[models.NVD]; ok {
			message[KeyCWEID] = content.CweID
			if config.Conf.Kinesis.Verbose {
				message[KeySourceLink] = content.SourceLink
				message[KeySummary] = content.Summary
			}
		}

		if config.Conf.Kinesis.ExtraFields != nil {
			for key, value := range config.Conf.Kinesis.ExtraFields {
				message[key] = value
			}
		}

		output, err := json.Marshal(message)
		if err != nil {
			return nil, err
		}
		messages = append(messages, output)
	}
	return messages, nil
}
