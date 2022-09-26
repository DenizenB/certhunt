CREATE TABLE IF NOT EXISTS certs (
    common_name VARCHAR(253),
    domain VARCHAR(253),
    suffix VARCHAR(253),
    all_domains VARCHAR(253)[],
    seen INTEGER,
    validity_seconds INTEGER
);

CREATE INDEX IF NOT EXISTS certs_index ON certs (seen, common_name);

CREATE OR REPLACE VIEW newest AS
    SELECT common_name, TO_TIMESTAMP(seen)
        FROM certs
        ORDER BY seen DESC;

CREATE OR REPLACE VIEW top_suffix AS
	SELECT suffix, COUNT(*)
		FROM certs
		GROUP BY suffix
		ORDER BY count DESC;

CREATE OR REPLACE VIEW sus_banks AS
	SELECT CONCAT('https://', common_name) AS url, TO_TIMESTAMP(MAX(seen)) AS time
		FROM certs
		WHERE
            (common_name ILIKE '%bank%' OR common_name ILIKE '%seb%' OR common_name ILIKE '%sbab%')
			AND common_name ~* '\y(bankid|handelsbanken|swedbank|nordea|seb|seblt|danskebank|sbab|skandiabanken|icabanken)\y'
        GROUP BY common_name
		ORDER BY MAX(seen) DESC;
