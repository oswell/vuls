/* Vuls - Vulnerability Scanner
Copyright (C) 2016  Future Architect, Inc. Japan.

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
    "fmt"
    "strings"
    "io/ioutil"
    "crypto/tls"
	"crypto/x509"
    "encoding/json"
    "github.com/Shopify/sarama"

    log "github.com/Sirupsen/logrus"
    c "github.com/future-architect/vuls/config"
    "github.com/future-architect/vuls/models"
)

// Requires new configuration parameters.
// KafkaTLSCertificate   *string
// KafkaTLSKey           *string
// KafkaTLSCACertificate *string

// KafkaWriter writes results to a kafka topic
type KafkaWriter struct{}

// Write results to Kafka
func (w KafkaWriter) Write(scanResults []models.ScanResult) (err error) {

    var jsonBytes []byte
    config := sarama.NewConfig()
    config.Producer.RequiredAcks = sarama.WaitForAll
    config.Producer.Retry.Max = 10

    tlsConfig, err := w.createTLSConfiguration() ; if tlsConfig != nil {
        config.Net.TLS.Config = tlsConfig
        config.Net.TLS.Enable = true
    }

    brokerList := strings.Split(c.Conf.KafkaBrokers, ",")
    producer, err := sarama.NewSyncProducer(brokerList, config)
	if err != nil {
		return fmt.Errorf("Failed to start Sarama producer: %s", err)
	}
    defer func() {
        if err := producer.Close(); err != nil {
            log.Errorf("Error: %v\n", err)
        }
    }()


    for _, r := range scanResults {
        if jsonBytes, err = json.Marshal(r); err != nil {
            return fmt.Errorf("Failed to Marshal to JSON: %s", err)
        }

        // Upload JSON to kafka.
        message := &sarama.ProducerMessage{Topic: c.Conf.KafkaTopic, Value: sarama.StringEncoder(jsonBytes)}
        partition, offset, err := producer.SendMessage(message)
        if err != nil {
            log.Errorf("FAILED to send message: %s\n", err)
        } else {
            log.Debugf("> message sent to partition %d at offset %d\n", partition, offset)
        }
    }

    return nil
}

// createTLSConfiguration configures TLS support for kafka connections
func (w KafkaWriter) createTLSConfiguration() (tlsConfig *tls.Config, err error) {

	if c.Conf.KafkaTLSCertificate != "" && c.Conf.KafkaTLSKey != "" && c.Conf.KafkaTLSCACertificate != "" {

    	cert, err := tls.LoadX509KeyPair(c.Conf.KafkaTLSCertificate, c.Conf.KafkaTLSKey) ; if err != nil {
            return nil, fmt.Errorf("Error loading key pair, %s", err)
		}

		caCert, err := ioutil.ReadFile(c.Conf.KafkaTLSCACertificate) ; if err != nil {
			return nil, fmt.Errorf("Error loading CA certificate, %s", err)
		}

		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(caCert)

		tlsConfig = &tls.Config{
			Certificates:       []tls.Certificate{cert},
			RootCAs:            certPool,
			InsecureSkipVerify: c.Conf.KafkaTLSVerify,
		}
	}

	return tlsConfig, nil
}
