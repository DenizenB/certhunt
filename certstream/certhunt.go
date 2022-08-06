package main

import (
    "os"
    "time"

    logging "github.com/op/go-logging"

    "github.com/CaliDog/certstream-go"
    "golang.org/x/net/publicsuffix"

    "database/sql"
    _ "github.com/lib/pq"

    "github.com/paulbellamy/ratecounter"
)

var log = logging.MustGetLogger("certhunt")
var logFormatter = logging.MustStringFormatter(`%{color}%{shortfunc} ▶ %{level:.4s}%{color:reset} %{message}`)

type Domain struct {
    Domain string
    Suffix string
    Seen uint64
}

func streamDomains(outputStream chan<- Domain) {
    var lastReport = time.Now()

    countSpan := 10 * time.Second
    certCount := ratecounter.NewRateCounter(countSpan)
    domainCount := ratecounter.NewRateCounter(countSpan)

    certs, errors := certstream.CertStreamEventStream(true)
    for {
        select {
            case jq := <-certs:
                messageType, _ := jq.String("message_type")
                if messageType != "certificate_update" {
                    continue
                }

                certCount.Incr(1)

                commonName, _ := jq.String("data", "leaf_cert", "subject", "CN")
                domain, err := publicsuffix.EffectiveTLDPlusOne(commonName)
                if err != nil  || domain != commonName {
                    continue
                }

                domainCount.Incr(1)

                suffix, _ := publicsuffix.PublicSuffix(domain)
                seen, _ := jq.Float("data", "seen")

                result := Domain {
                    Domain: domain,
                    Suffix: suffix,
                    Seen: uint64(seen),
                }

                outputStream<- result
            case err := <-errors:
                log.Error(err)
        }

        if time.Since(lastReport) >= countSpan {
            certRate := float64(certCount.Rate()) / countSpan.Seconds()
            domainRate := float64(domainCount.Rate()) / countSpan.Seconds()

            log.Info(certRate, "certs/s", domainRate, "domains/s")
            lastReport = time.Now()
        }
    }
}

func storeDomains(inputStream <-chan Domain) {
    database := os.Getenv("POSTGRES_DB")
    password := os.Getenv("POSTGRES_PASSWORD")
    connStr := "host=postgres user=postgres sslmode=disable password=" + password + " dbname=" + database

    db, err := sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal(err)
    }

    defer db.Close()

    batchSize := 1000
    var domains [1000]Domain

    for {
        // Fetch batch of domains
        for i := 0; i < batchSize; i++ {
            domains[i] = <-inputStream
        }

        // Insert batch of domains
        tx, err := db.Begin()
        if err != nil {
            log.Error(err)
            continue
        }

        for i := 0; i < batchSize; i++ {
            _, err := db.Exec("INSERT INTO domains (domain, suffix, seen) VALUES ($1, $2, $3)", domains[i].Domain, domains[i].Suffix, domains[i].Seen)
            if err != nil {
                log.Error(err)
            }
        }

        err = tx.Commit()
        if err != nil {
            log.Error(err)
            continue
        }

        log.Info("Batch of", batchSize, "domains inserted")
    }
}

func main() {
    logging.SetFormatter(logFormatter)

    log.Info("Initializing")
    domains := make(chan Domain)
    go streamDomains(domains)
    storeDomains(domains)
}
