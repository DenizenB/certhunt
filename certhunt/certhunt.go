package main

import (
    "os"
    "time"
    "strings"
    "encoding/json"
    "fmt"
    "bufio"
    "context"

    logging "github.com/op/go-logging"
    "github.com/CaliDog/certstream-go"
    "github.com/jmoiron/jsonq"
    "github.com/paulbellamy/ratecounter"
    "golang.org/x/net/publicsuffix"
    "github.com/go-redis/redis/v8"
)

type MispAttribute struct {
    ParentEventUuid string `json:"parent_event_uuid"`
    EventName string `json:"event_name"`
    EventTags []string `json:"event_tags"`
    Type string `json:"attr_type"`
    Value string `json:"attr_value"`
    Comment string `json:"attr_comment"`
}

func (ma MispAttribute) fillDefaults() MispAttribute {
    ma.Type = "domain"
    // TODO set uuid of parent event
    //ma.ParentEventUuid = ""
    return ma
}

var log = logging.MustGetLogger("certhunt")

func streamCerts(certs chan<- map[string]interface{}) {
    printInterval := 10 * time.Second
    var lastPrint = time.Now()

    averageInterval := printInterval
    msgCounter := ratecounter.NewRateCounter(averageInterval)
    certCounter := ratecounter.NewRateCounter(averageInterval)

    log.Debug("Connecting to Certstream")
    events, errors := certstream.CertStreamEventStream(false)
    for {
        select {
            case jq := <-events:
                msgCounter.Incr(1)

                // Ignore heartbeats
                if messageType, _ := jq.String("message_type"); messageType != "certificate_update" {
                    continue
                }

                // Ignore pre-cert entries
                if updateType, _ := jq.String("data", "update_type"); updateType == "PrecertLogEntry" {
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

                certs<- data
            case err := <-errors:
                log.Debug(err)
        }

        if time.Since(lastPrint) >= printInterval {
            msgRate := float64(msgCounter.Rate()) / averageInterval.Seconds()
            certRate := float64(certCounter.Rate()) / averageInterval.Seconds()

            log.Debugf("%0.f certs/s (%0.f messages/s)", certRate, msgRate)
            lastPrint = time.Now()
        }
    }
}

func matchCerts(worker int, certs <-chan map[string]interface{}, attributes chan<- MispAttribute) {
    // Load rules
    ruleset, err := LoadRules("./rules")
    if err != nil {
        log.Fatal(err)
    }

    log.Debugf("Worker %d: Loaded %d/%d rules (%d failed, %d unsupported)",
        worker, ruleset.Ok, ruleset.Total, ruleset.Failed, ruleset.Unsupported)

    // Match certs
    for {
        certData := <-certs
        event := DynamicMap(certData)

        for _, rule := range ruleset.Rules {
            if result, match := rule.Eval(event); match {
                jq := jsonq.NewQuery(certData)

                fingerprint, _ := jq.String("leaf_cert", "fingerprint")
                fingerprint = strings.ToLower(strings.ReplaceAll(fingerprint, ":", ""))
                log.Infof("Match for \"%s\" (%s)", result.Title, fingerprint)

                seenUnix, _ := jq.Float("seen")
                seenDate := time.Unix(int64(seenUnix), 0).Format("2006-01-02")
                comment := fmt.Sprintf("Certificate issued: %s\nCertificate sha1: %s", seenDate, fingerprint)

                values, err := jq.ArrayOfStrings("leaf_cert", "registered_domains")
                if err != nil || len(values) == 0 {
                    log.Error("Failed to resolve registered domains for certificate")
                    continue
                }

                for _, value := range values {
                    attribute := MispAttribute{
                        EventName: result.Title,
                        EventTags: result.Tags,
                        Value: value,
                        Comment: comment,
                    }.fillDefaults()

                    attributes<- attribute
                }

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

func createAttributes(attributes chan MispAttribute) {
    // Connect to redis
    rdb := redis.NewClient(&redis.Options{
        Addr: "redis:6379",
        DB:   1,
    })
    ctx := context.Background()

    // Open output file
    file, err := os.OpenFile("attributes.jsonl", os.O_CREATE | os.O_APPEND | os.O_WRONLY, 0644)
    if err != nil {
        log.Fatal(err)
    }
    defer file.Close()
    writer := bufio.NewWriter(file)

    for {
        attribute := <-attributes
        redisKey := "attr:" + attribute.EventName + ":" + attribute.Value

        // Check if already added
        if rdb.Get(ctx, redisKey).Err() != redis.Nil {
            // Already added
            log.Debugf("Attribute '%s' already added to MISP event '%s', skipping", attribute.Value, attribute.EventName)
            continue
        }

        // Write json to file
        jsonAttr, err := json.Marshal(attribute)
        if err != nil {
            log.Errorf("failed to json encode: %s", err)
            continue
        }
        writer.WriteString(string(jsonAttr) + "\n")
        writer.Flush()

        // Publish message to redis
        if err := rdb.Publish(ctx, "certhunt:attributes", jsonAttr).Err(); err != nil {
            log.Errorf("failed to publish message: %s", err)
        }

        // Add to redis to avoid duplicate attributes
        if err := rdb.SetNX(ctx, redisKey, "", 90*24*time.Hour).Err(); err != nil {
            log.Errorf("failed to set redis key '%s': %s", redisKey, err)
        }
    }
}

func main() {
    setupLogging()

    certs := make(chan map[string]interface{})
    attributes := make(chan MispAttribute)

    workerCount := 5
    for id := 1; id <= workerCount; id++ {
        go matchCerts(id, certs, attributes)
    }

    go createAttributes(attributes)

    streamCerts(certs)
}
