package main

import (
    "os"
    "time"
    "strings"

    logging "github.com/op/go-logging"
    "github.com/CaliDog/certstream-go"
    "github.com/paulbellamy/ratecounter"
    "golang.org/x/exp/slices"
    "golang.org/x/net/publicsuffix"
)

var log = logging.MustGetLogger("certhunt")

func streamCerts(outputStream chan<- DynamicMap) {
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
                if leaf_cert, ok := data["leaf_cert"]; ok {
                    leaf_cert := leaf_cert.(map[string]interface{})

                    if all_domains, ok := leaf_cert["all_domains"]; ok {
                        all_domains := all_domains.([]interface{})

                        registered_domains := make([]string, 0)
                        for _, domain := range all_domains {
                            registered_domain, err := publicsuffix.EffectiveTLDPlusOne(domain.(string))
                            if err != nil {
                                log.Debug(err)
                                continue
                            }

                            if !slices.Contains(registered_domains, registered_domain) {
                                registered_domains = append(registered_domains, registered_domain)
                            }
                        }

                        leaf_cert["registered_domains"] = registered_domains
                    }
                }

                outputStream<- DynamicMap(data)
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

func matchCerts(inputStream <-chan DynamicMap) {
    // Load rules
    log.Debug("Loading Sigma rules")
    ruleset, err := LoadRules("./rules")
    if err != nil {
        log.Fatal(err)
    }

    // Match certs
    for {
        cert_data := <-inputStream

        for _, rule := range ruleset.Rules {
            if result, match := rule.Eval(cert_data); match {
                // TODO how do we access the important fields of the rule? Rule objects are completely inaccessible?
                allDomains, _ := cert_data.Select("leaf_cert.registered_domains")
                fingerprint, _ := cert_data.Select("leaf_cert.fingerprint")
                fingerprint = strings.ToLower(strings.ReplaceAll(fingerprint.(string), ":", ""))

                log.Infof("Match for \"%s\": %s (%s)", result.Title, allDomains, fingerprint)
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

    certs := make(chan DynamicMap)

    workerCount := 5
    for i := 0; i < workerCount; i++ {
        go matchCerts(certs)
    }

    streamCerts(certs)
}
