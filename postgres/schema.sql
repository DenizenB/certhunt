CREATE TABLE IF NOT EXISTS domains (
    domain VARCHAR(253) PRIMARY KEY,
    suffix VARCHAR(253),
    seen INTEGER
);

CREATE OR REPLACE RULE replace_into_domains AS
	ON INSERT TO domains
    	WHERE EXISTS (SELECT 1 FROM domains WHERE domains.domain = new.domain)
    DO INSTEAD UPDATE domains
        SET seen = new.seen
        WHERE domains.domain = new.domain;

CREATE OR REPLACE VIEW top_suffix AS
	SELECT suffix, COUNT(*)
		FROM domains
		GROUP BY suffix
		ORDER BY count DESC;

CREATE OR REPLACE VIEW sus_banks AS
	SELECT domain, suffix, TO_TIMESTAMP(seen) AS seen
		FROM domains
		WHERE
			domain ~ '\y(bankid|handelsbanken|swedbank|nordea|seb|seblt|danskebank|sbab|skandiabanken|icabanken)\y'
		ORDER BY seen DESC;
