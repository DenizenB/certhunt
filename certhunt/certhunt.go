package main

import (
    "os"
    "time"
    "strings"
    "encoding/json"
    "fmt"

    logging "github.com/op/go-logging"
    "github.com/CaliDog/certstream-go"
    "github.com/jmoiron/jsonq"
    "github.com/paulbellamy/ratecounter"
    "golang.org/x/net/publicsuffix"
)

type MispAttribute struct {
    ParentEvent string `json:"parent_event"`
    Event string `json:"event"`
    EventTags []string `json:"event_tags"`
    Type string `json:"type"`
    Value string `json:"value"`
    Comment string `json:"comment"`
}

var log = logging.MustGetLogger("certhunt")

func streamCerts(outputStream chan<- map[string]interface{}) {
    printInterval := 10 * time.Second
    var lastPrint = time.Now()

    averageInterval := printInterval
    certCounter := ratecounter.NewRateCounter(averageInterval)

    log.Debug("Connecting to Certstream")
    certs, errors := certstream.CertStreamEventStream(false)
    for {
        select {
            case jq := <-certs:
                messageType, _ := jq.String("message_type")
                if messageType != "certificate_update" {
                    continue
                }

                certCounter.Incr(1)

                data, _ := jq.Object("data")

                // Enrich message
                if leafCert, ok := data["leaf_cert"]; ok {
                    leafCert := leafCert.(map[string]interface{})

                    if allDomains, ok := leafCert["all_domains"]; ok {
                        allDomains := allDomains.([]interface{})

                        registeredDomains := make([]interface{}, 0)
                        alreadyAdded := map[string]struct{}{}
                        for _, domain := range allDomains {
                            registeredDomain, err := publicsuffix.EffectiveTLDPlusOne(domain.(string))
                            if err != nil {
                                log.Debug(err)
                                continue
                            }

                            if _, exists := alreadyAdded[registeredDomain]; !exists {
                                alreadyAdded[registeredDomain] = struct{}{}
                                registeredDomains = append(registeredDomains, registeredDomain)
                            }
                        }

                        leafCert["registered_domains"] = registeredDomains
                    }
                }

                outputStream<- data
            case err := <-errors:
                log.Debug(err)
        }

        if time.Since(lastPrint) >= printInterval {
            certRate := float64(certCounter.Rate()) / averageInterval.Seconds()

            log.Debug(certRate, "certs/s")
            lastPrint = time.Now()
        }
    }
}

func matchCerts(inputStream <-chan map[string]interface{}) {
    // Load rules
    log.Debug("Loading Sigma rules")
    ruleset, err := LoadRules("./rules")
    if err != nil {
        log.Fatal(err)
    }

    // Match certs
    for {
        certData := <-inputStream
        event := DynamicMap(certData)

        for _, rule := range ruleset.Rules {
            if result, match := rule.Eval(event); match {
                jq := jsonq.NewQuery(certData)

                fingerprint, _ := jq.String("leaf_cert", "fingerprint")
                fingerprint = strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
                log.Infof("Match for \"%s\" (%s)", result.Title, fingerprint)

                seenUnix, _ := jq.Float("seen")
                seenDate := time.Unix(int64(seenUnix), 0).Format("2006-01-02")
                registeredDomains, err := jq.ArrayOfStrings("leaf_cert", "registered_domains")
                if err != nil {
                    log.Error(err)
                    continue
                }

                if len(registeredDomains) == 0 {
                    // No registered domain, no attribute
                    log.Error("Failed to resolve registered domains for certificate")
                    continue
                }

                attribute := MispAttribute{
                    ParentEvent: "Certstream Sigma Rules",
                    Event: result.Title,
                    EventTags: result.Tags,
                    Type: "domain",
                    Value: registeredDomains[0],
                    Comment: "Observed in Certstream: " + seenDate,
                }

                jsonAttr, err := json.Marshal(attribute)
                if err != nil {
                    log.Error(err)
                    continue
                }

                fmt.Println(string(jsonAttr))
            }
        }
    }
}

func setupLogging() {
    // Log to file
    logFile, err := os.OpenFile("certhunt.log", os.O_RDWR | os.O_CREATE | os.O_APPEND, 0666)
    if err != nil {
        log.Fatal("Failed to open log file:", err)
    }

    backendConsole := logging.NewLogBackend(os.Stderr, "", 0)
    backendFile    := logging.NewLogBackend(logFile, "", 0)

    formatConsole := logging.MustStringFormatter(`%{color}%{shortfunc} ▶ %{level:.4s}%{color:reset} %{message}`)
    formatFile    := logging.MustStringFormatter(`%{time:2006-01-02T15:04:05} %{level} %{message}`)

    backendConsoleFormatter := logging.NewBackendFormatter(backendConsole, formatConsole)
    backendFileFormatter    := logging.NewBackendFormatter(backendFile, formatFile)

    backendFileLeveled := logging.AddModuleLevel(backendFileFormatter)
    backendFileLeveled.SetLevel(logging.INFO, "")

    logging.SetBackend(backendConsoleFormatter, backendFileLeveled)
}

func main() {
    setupLogging()

    certs := make(chan map[string]interface{})

    workerCount := 5
    for i := 0; i < workerCount; i++ {
        go matchCerts(certs)
    }

    streamCerts(certs)
}
