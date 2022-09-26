package main

import (
    "os"
    "time"
    "strings"

    logging "github.com/op/go-logging"

    "github.com/CaliDog/certstream-go"
    "golang.org/x/net/publicsuffix"

    "database/sql"
    "github.com/lib/pq"

    "github.com/paulbellamy/ratecounter"
)

var log = logging.MustGetLogger("certhunt")
var logFormatter = logging.MustStringFormatter(`%{color}%{shortfunc} ▶ %{level:.4s}%{color:reset} %{message}`)

type Certificate struct {
    CommonName string
    Domain string
    Suffix string
    AllDomains []string
    Seen uint64
    ValiditySeconds uint64
}

func streamCerts(outputStream chan<- Certificate) {
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

                seen, _ := jq.Float("data", "seen")
                notBefore, _ := jq.Float("data", "leaf_cert", "not_before")
                notAfter, _ := jq.Float("data", "leaf_cert", "not_after")
                commonName, _ := jq.String("data", "leaf_cert", "subject", "CN")
                allDomains, _ := jq.ArrayOfStrings("data", "leaf_cert", "all_domains")

                var domain string
                var suffix string
                var err error

                if commonName == "" {
                    domain = ""
                    suffix = ""
                } else {
                    if domain, err = publicsuffix.EffectiveTLDPlusOne(commonName); err != nil {
                        log.Warning(err)
                        domain = ""
                    }

                    suffix, _ = publicsuffix.PublicSuffix(domain)
                }

                for i := 0; i < len(allDomains); i++ {
                    prefix := strings.TrimSuffix(allDomains[i], commonName)
                    prefix = strings.TrimSuffix(prefix, domain)
                    prefix = strings.TrimSuffix(prefix, ".")
                    allDomains[i] = prefix
                    // TODO remove empty string from array
                }

                domainCount.Incr(int64(len(allDomains)))

                result := Certificate {
                    CommonName: commonName,
                    Domain: domain,
                    Suffix: suffix,
                    AllDomains: allDomains,
                    Seen: uint64(seen),
                    ValiditySeconds: uint64(notAfter - notBefore),
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

func storeCerts(inputStream <-chan Certificate) {
    database := os.Getenv("POSTGRES_DB")
    password := os.Getenv("POSTGRES_PASSWORD")
    connStr := "host=postgres user=postgres sslmode=disable password=" + password + " dbname=" + database

    db, err := sql.Open("postgres", connStr)
    if err != nil {
        log.Fatal(err)
    }

    defer db.Close()

    batchSize := 1000
    var certs [1000]Certificate
    var count int

    for {
        // Fetch batch of certs
        for i := 0; i < batchSize; i++ {
            certs[i] = <-inputStream
        }

        log.Info("Inserting batch of", batchSize, "certs")

        // Insert batch of certs
        tx, err := db.Begin()
        if err != nil {
            log.Error(err)
            continue
        }

        for i := 0; i < batchSize; i++ {
            _, err := tx.Exec("INSERT INTO certs (common_name, domain, suffix, all_domains, seen, validity_seconds) VALUES ($1, $2, $3, $4, $5, $6)",
                certs[i].CommonName, certs[i].Domain, certs[i].Suffix, pq.Array(certs[i].AllDomains), certs[i].Seen, certs[i].ValiditySeconds)
            if err != nil {
                log.Error(err)
            }
        }

        err = tx.Commit()
        if err != nil {
            log.Error(err)
            continue
        }

        log.Info("Batch inserted")

        // Check table size
        row := db.QueryRow("SELECT COUNT(*) FROM certs")
        err = row.Scan(&count)
        if err != nil {
            log.Error(err)
            continue
        }

        if count > 2500000 {
            log.Info(count, "rows in table, trimming oldest 10k rows")
            _, err = db.Exec("DELETE FROM certs WHERE ctid IN (SELECT ctid FROM certs ORDER BY seen LIMIT 10000)")
            if err != nil {
                log.Error(err)
            }
        }
    }
}

func main() {
    logging.SetFormatter(logFormatter)

    log.Info("Initializing")
    certs := make(chan Certificate, 2000)
    go streamCerts(certs)
    storeCerts(certs)
}
