CREATE TABLE IF NOT EXISTS domains (
    domain VARCHAR(253) PRIMARY KEY,
    suffix VARCHAR(253),
    seen INTEGER
);

CREATE INDEX IF NOT EXISTS domains_seen ON domains (
    seen DESC
);

CREATE OR REPLACE RULE replace_into_domains AS
	ON INSERT TO domains
    	WHERE EXISTS (SELECT 1 FROM domains WHERE domains.domain = new.domain)
    DO INSTEAD UPDATE domains
        SET seen = new.seen
        WHERE domains.domain = new.domain;

CREATE OR REPLACE RULE max_table_size AS
    ON INSERT TO domains
        WHERE (SELECT COUNT(*) from domains) > 2500000
    DO ALSO DELETE FROM domains
        WHERE ctid IN (
            SELECT ctid
                FROM domains
                ORDER BY seen
                LIMIT 1
        );

CREATE OR REPLACE VIEW newest AS
    SELECT domain, suffix, TO_TIMESTAMP(seen)
        FROM domains
        ORDER BY seen DESC;

CREATE OR REPLACE VIEW top_suffix AS
	SELECT suffix, COUNT(*)
		FROM domains
		GROUP BY suffix
		ORDER BY count DESC;

CREATE OR REPLACE VIEW sus_banks AS
	SELECT CONCAT('https://', domain) AS url, TO_TIMESTAMP(seen) AS seen
		FROM domains
		WHERE
            (domain ILIKE '%bank%' OR domain ILIKE '%seb%' OR domain ILIKE '%sbab%')
			AND domain ~* '\y(bankid|handelsbanken|swedbank|nordea|seb|seblt|danskebank|sbab|skandiabanken|icabanken)\y'
		ORDER BY seen DESC;
