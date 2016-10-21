// The MIT License (MIT)
// Copyright (c) 2016 Christian Parpart <trapni@gmail.com>
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/ec2"
	"github.com/gorilla/mux"
	flag "github.com/ogier/pflag"
)

const appVersion = "0.1.0"

var (
	ErrUserOrPasswordEmpty = errors.New("Username or password empty.")
)

type awsFund struct {
	httpPort             int
	awsImageId           string
	awsAccessKeyId       string
	awsSecretAccessKey   string
	awsSecurityGroupName string
	awsKeyName           string
	awsInstanceType      string
	awsRegion            string
	svc                  *ec2.EC2
}

func (fund *awsFund) initialize() {
	if fund.awsAccessKeyId != "" {
		os.Setenv("AWS_ACCESS_KEY_ID", fund.awsAccessKeyId)
	}

	if fund.awsSecretAccessKey != "" {
		os.Setenv("AWS_SECRET_ACCESS_KEY", fund.awsSecretAccessKey)
	}

	fund.svc = ec2.New(session.New(), &aws.Config{Region: aws.String(fund.awsRegion)})
}

func (fund *awsFund) Run() {
	fund.initialize()

	// setting up HTTP router
	router := mux.NewRouter()
	router.HandleFunc("/ping", fund.v0Ping)
	router.HandleFunc("/version", fund.v0Version)

	v1 := router.PathPrefix("/v1").Subrouter()
	v1.HandleFunc("/instances", fund.v1Instances).Methods("GET")
	v1.HandleFunc("/instances/create", fund.v1CreateInstance).Methods("POST")

	// start listening and serving on incoming HTTP requests
	httpAddr := fmt.Sprintf("%v:%v", "0.0.0.0", fund.httpPort)
	log.Printf("Listening for backend API requests on http://%v", httpAddr)
	err := http.ListenAndServe(httpAddr, router)
	if err != nil {
		panic(err)
	}
}

// ===========================================================================
// AWS helpers

func (fund *awsFund) awsCreateInstance(username, password string) (*ec2.Reservation, error) {
	if username == "" || password == "" {
		return nil, ErrUserOrPasswordEmpty
	}

	// create new local user and whitelist that user for SSH password auth
	//
	// XXX it would be better to use a customized AMI image instead of hacking
	// into the sshd_config here.
	// XXX we may want to add him to the sudoers group here, so he can root.
	// But this is discouraged. Use the passwd key-pair for that instead.
	awsUserData := fmt.Sprintf("#! /bin/bash\n"+
		"set -ex\n"+
		"useradd -m %v\n"+
		"echo %v:%v | chpasswd\n"+
		"echo \"Match User %v\" >> /etc/ssh/sshd_config\n"+
		"echo \"  PasswordAuthentication yes\" >> /etc/ssh/sshd_config\n"+
		"restart ssh\n",
		username, username, password, username)

	// base64-encode
	awsUserData = base64.StdEncoding.EncodeToString([]byte(awsUserData))

	params := &ec2.RunInstancesInput{
		ImageId:                           aws.String(fund.awsImageId),
		MaxCount:                          aws.Int64(1),
		MinCount:                          aws.Int64(1),
		KeyName:                           aws.String(fund.awsKeyName),
		UserData:                          aws.String(awsUserData),
		InstanceType:                      aws.String(fund.awsInstanceType),
		InstanceInitiatedShutdownBehavior: aws.String("terminate"),
		SecurityGroupIds: []*string{
			aws.String(fund.awsSecurityGroupName),
		},
		Monitoring: &ec2.RunInstancesMonitoringEnabled{
			Enabled: aws.Bool(true),
		},
	}

	// XXX usually it's not a wise choice to log passwords
	log.Printf("Creating instance with username %q and password %q.\n", username, password)
	reservation, err := fund.svc.RunInstances(params)
	if err != nil {
		return nil, err
	}

	return reservation, nil
}

func (fund *awsFund) awsInstanceById(id *string) (*ec2.Instance, error) {
	input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("instance-id"),
				Values: []*string{id},
			},
		},
	}

	resp, err := fund.svc.DescribeInstances(input)
	if err != nil {
		return nil, err
	}

	return resp.Reservations[0].Instances[0], nil
}

func (fund *awsFund) awsWaitForInstanceToRun(id *string) error {
	params := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name:   aws.String("instance-id"),
				Values: []*string{id},
			},
		},
	}

	log.Printf("Waiting for instance to run: %v\n", *id)
	return fund.svc.WaitUntilInstanceRunning(params)
}

// ===========================================================================
// HTTP API

func (fund *awsFund) v0Ping(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, "pong\n")
}

func (fund *awsFund) v0Version(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "awsfund %v\n", appVersion)
}

func (fund *awsFund) v1Instances(w http.ResponseWriter, r *http.Request) {
	input := &ec2.DescribeInstancesInput{
		Filters: []*ec2.Filter{
			&ec2.Filter{
				Name: aws.String("instance-state-name"),
				Values: []*string{
					aws.String("running"),
					aws.String("terminated"),
					aws.String("pending"),
				},
			},
		},
	}

	resp, err := fund.svc.DescribeInstances(input)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%s\n", err)
		return
	}

	w.Header().Set("content-type", "text/csv")
	w.WriteHeader(http.StatusOK)

	fmt.Fprintln(w, "reservation-id instance-id instance-state key-name, public-ip")
	for _, res := range resp.Reservations {
		for _, inst := range res.Instances {
			fmt.Fprint(w, *res.ReservationId)
			fmt.Fprint(w, " ", *inst.InstanceId)
			fmt.Fprint(w, " ", *inst.State.Name)
			fmt.Fprint(w, " ", *inst.KeyName)
			if inst.PublicIpAddress != nil {
				fmt.Fprint(w, " ", *inst.PublicIpAddress)
			} else {
				fmt.Fprint(w, " -")
			}
			fmt.Fprintln(w)
		}
	}
}

func (fund *awsFund) v1CreateInstance(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	password := r.URL.Query().Get("password")
	reservation, err := fund.awsCreateInstance(username, password)
	if err != nil {
		if err == ErrUserOrPasswordEmpty {
			w.WriteHeader(http.StatusBadRequest)
		} else {
			w.WriteHeader(http.StatusInternalServerError)
		}
		fmt.Fprintf(w, "%v\n", err)
		return
	}

	fund.awsWaitForInstanceToRun(reservation.Instances[0].InstanceId)

	i, err := fund.awsInstanceById(reservation.Instances[0].InstanceId)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "%v\n", err)
		return
	}

	// provide some additional information as HTTP response headers (easy to
	// parse in client APIs)
	w.Header().Add("public-ip", *i.PublicIpAddress)
	w.Header().Add("public-dns", *i.PublicDnsName)
	w.Header().Add("instance-id", *i.InstanceId)

	// set HTTP status code to: 201 (Created)
	w.WriteHeader(http.StatusCreated)

	// also provide public IP address via HTTP response body
	fmt.Fprintf(w, "%v\n", *i.PublicIpAddress)
}

// ===========================================================================
// entrypoint

func main() {
	fund := awsFund{}

	flag.StringVar(&fund.awsAccessKeyId, "aws-access-key-id", "", "AWS access key ID")
	flag.StringVar(&fund.awsImageId, "aws-image-id", "ami-26c43149", "AWS AMI image ID")
	flag.StringVar(&fund.awsSecretAccessKey, "aws-secret-access-key", "", "AWS secret access key")
	flag.StringVar(&fund.awsSecurityGroupName, "aws-sg-name", "default", "AWS security group")
	flag.StringVar(&fund.awsKeyName, "aws-key-name", "", "AWS key name")
	flag.StringVar(&fund.awsInstanceType, "aws-instance-type", "t2.micro", "AWS instance type")
	flag.StringVar(&fund.awsRegion, "aws-region", "eu-central-1", "")
	flag.IntVar(&fund.httpPort, "http-port", 8080, "HTTP port to accept backend API requests from")
	flag.Parse()

	fund.Run()
}
