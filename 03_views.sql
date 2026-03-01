USE cyber_threat_intelligence;


-- VIEW 1: threat_risk_intelligence
-- Attack breakdown by protocol and category

CREATE OR REPLACE VIEW threat_risk_intelligence AS
SELECT
    proto,
    attack_cat,
    COUNT(*)                      AS event_count,
    ROUND(AVG(rate), 4)           AS avg_rate,
    ROUND(AVG(label), 4)          AS avg_attack_probability
FROM network_traffic
GROUP BY proto, attack_cat;


-- VIEW 2: top_attack_categories
-- Top network attack categories ranked by volume

CREATE OR REPLACE VIEW top_attack_categories AS
SELECT
    attack_cat,
    COUNT(*)                                    AS total_events,
    SUM(label)                                  AS confirmed_attacks,
    ROUND(SUM(label) / COUNT(*) * 100, 2)       AS attack_pct,
    ROUND(AVG(rate), 4)                         AS avg_rate,
    ROUND(AVG(sbytes + dbytes), 0)              AS avg_total_bytes
FROM network_traffic
GROUP BY attack_cat
ORDER BY total_events DESC;

-- VIEW 3: phishing_summary
-- Phishing vs legitimate URL feature comparison

CREATE OR REPLACE VIEW phishing_summary AS
SELECT
    phishing,
    COUNT(*)                              AS total_urls,
    ROUND(AVG(length_url), 2)            AS avg_url_length,
    ROUND(AVG(qty_dot_url), 2)           AS avg_dots_in_url,
    ROUND(AVG(qty_hyphen_url), 2)        AS avg_hyphens_in_url,
    ROUND(AVG(directory_length), 2)      AS avg_directory_length,
    ROUND(AVG(qty_redirects), 2)         AS avg_redirects,
    ROUND(AVG(tls_ssl_certificate), 2)   AS avg_has_tls,
    ROUND(AVG(domain_in_ip), 2)          AS avg_ip_as_domain,
    ROUND(AVG(url_shortened), 2)         AS avg_url_shortened,
    ROUND(AVG(qty_params), 2)            AS avg_qty_params
FROM phishing_urls
GROUP BY phishing;

-- VIEW 4: high_risk_traffic
-- Network attacks with anomalously high byte transfer

CREATE OR REPLACE VIEW high_risk_traffic AS
SELECT
    id,
    proto,
    attack_cat,
    rate,
    sbytes,
    dbytes,
    (sbytes + dbytes)               AS total_bytes,
    label
FROM network_traffic
WHERE label = 1
  AND (sbytes + dbytes) > (
      SELECT AVG(sbytes + dbytes) + 2 * STDDEV(sbytes + dbytes)
      FROM network_traffic
      WHERE label = 1
  )
ORDER BY total_bytes DESC;

-- VIEW 5: unified_threat_landscape

CREATE OR REPLACE VIEW unified_threat_landscape AS
SELECT
    'Network Traffic'                                           AS dataset,
    COUNT(*)                                                    AS total_records,
    SUM(label)                                                  AS confirmed_threats,
    ROUND(SUM(label) / COUNT(*) * 100, 2)                      AS threat_pct,
    ROUND(AVG(rate), 4)                                         AS avg_rate,
    ROUND(AVG(sbytes + dbytes), 0)                             AS avg_data_volume,
    NULL                                                        AS avg_url_length,
    NULL                                                        AS avg_redirects,
    NULL                                                        AS pct_no_tls,
    NULL                                                        AS pct_ip_as_domain
FROM network_traffic

UNION ALL

SELECT
    'Phishing URLs'                                             AS dataset,
    COUNT(*)                                                    AS total_records,
    SUM(phishing)                                               AS confirmed_threats,
    ROUND(SUM(phishing) / COUNT(*) * 100, 2)                   AS threat_pct,
    NULL                                                        AS avg_rate,
    NULL                                                        AS avg_data_volume,
    ROUND(AVG(length_url), 2)                                  AS avg_url_length,
    ROUND(AVG(qty_redirects), 2)                               AS avg_redirects,
    ROUND(SUM(CASE WHEN tls_ssl_certificate = 0 THEN 1 ELSE 0 END) / COUNT(*) * 100, 2) AS pct_no_tls,
    ROUND(SUM(domain_in_ip) / COUNT(*) * 100, 2)              AS pct_ip_as_domain
FROM phishing_urls;

-- VIEW 6: http_attack_vs_phishing_tls

CREATE OR REPLACE VIEW http_attack_vs_phishing_tls AS
SELECT
    'HTTP Network Attacks' AS threat_vector,
    COUNT(*)               AS total_events,
    SUM(label)             AS confirmed_threats,
    ROUND(SUM(label) / COUNT(*) * 100, 2) AS threat_pct,
    ROUND(AVG(rate), 4)    AS avg_rate,
    ROUND(AVG(sbytes + dbytes), 0) AS avg_bytes,
    NULL                   AS pct_no_tls
FROM network_traffic
WHERE service IN ('http', 'ftp', 'smtp', 'pop3', 'imap')

UNION ALL

SELECT
    'Phishing URLs Without TLS' AS threat_vector,
    COUNT(*)                    AS total_events,
    SUM(phishing)               AS confirmed_threats,
    ROUND(SUM(phishing) / COUNT(*) * 100, 2) AS threat_pct,
    NULL                        AS avg_rate,
    NULL                        AS avg_bytes,
    ROUND(SUM(CASE WHEN tls_ssl_certificate = 0 THEN 1 ELSE 0 END) / COUNT(*) * 100, 2) AS pct_no_tls
FROM phishing_urls
WHERE phishing = 1;

-- VIEW 7: ftp_attack_vs_phishing_email

CREATE OR REPLACE VIEW ftp_attack_vs_phishing_email AS
SELECT
    'FTP Network Attacks'  AS threat_vector,
    COUNT(*)               AS total_events,
    SUM(label)             AS confirmed_attacks,
    ROUND(SUM(label) / COUNT(*) * 100, 2)   AS attack_pct,
    ROUND(AVG(ct_ftp_cmd), 4)               AS avg_ftp_commands,
    SUM(is_ftp_login)                        AS total_ftp_logins,
    NULL                                     AS email_in_url_pct
FROM network_traffic
WHERE is_ftp_login = 1 OR ct_ftp_cmd > 0

UNION ALL

SELECT
    'Phishing URLs With Embedded Email' AS threat_vector,
    COUNT(*)                            AS total_events,
    SUM(phishing)                       AS confirmed_attacks,
    ROUND(SUM(phishing) / COUNT(*) * 100, 2) AS attack_pct,
    NULL                                AS avg_ftp_commands,
    NULL                                AS total_ftp_logins,
    ROUND(AVG(email_in_url) * 100, 2)  AS email_in_url_pct
FROM phishing_urls
WHERE email_in_url = 1;

-- VIEW 8: normalised_risk_score

CREATE OR REPLACE VIEW normalised_risk_score AS
SELECT
    'Network Traffic' AS dataset,
    ROUND(
        (SUM(label) / COUNT(*) * 100 * 0.6) +
        (SUM(CASE WHEN rate > 100000 THEN 1 ELSE 0 END) / COUNT(*) * 100 * 0.4),
    2) AS risk_score_0_to_100,
    SUM(label)                                      AS confirmed_threats,
    COUNT(*)                                        AS total_records,
    ROUND(SUM(label) / COUNT(*) * 100, 2)          AS base_threat_pct
FROM network_traffic

UNION ALL

SELECT
    'Phishing URLs' AS dataset,
    ROUND(
        (SUM(phishing) / COUNT(*) * 100 * 0.6) +
        (SUM(CASE WHEN tls_ssl_certificate = 0 THEN 1 ELSE 0 END) / COUNT(*) * 100 * 0.4),
    2) AS risk_score_0_to_100,
    SUM(phishing)                                   AS confirmed_threats,
    COUNT(*)                                        AS total_records,
    ROUND(SUM(phishing) / COUNT(*) * 100, 2)       AS base_threat_pct
FROM phishing_urls;

-- VIEW 9: dns_amplification_vs_phishing_domains

CREATE OR REPLACE VIEW dns_amplification_vs_phishing_domains AS
SELECT
    'DNS Network Attacks'  AS threat_vector,
    COUNT(*)               AS total_events,
    SUM(label)             AS confirmed_threats,
    ROUND(SUM(label) / COUNT(*) * 100, 2)   AS threat_pct,
    ROUND(AVG(sbytes + dbytes), 0)          AS avg_bytes,
    ROUND(AVG(rate), 4)                     AS avg_rate,
    NULL                                     AS avg_nameservers,
    NULL                                     AS pct_ip_as_domain
FROM network_traffic
WHERE service = 'dns'

UNION ALL

SELECT
    'Suspicious Phishing Domains' AS threat_vector,
    COUNT(*)                      AS total_events,
    SUM(phishing)                 AS confirmed_threats,
    ROUND(SUM(phishing) / COUNT(*) * 100, 2) AS threat_pct,
    NULL                          AS avg_bytes,
    NULL                          AS avg_rate,
    ROUND(AVG(qty_nameservers), 2) AS avg_nameservers,
    ROUND(SUM(domain_in_ip) / COUNT(*) * 100, 2) AS pct_ip_as_domain
FROM phishing_urls
WHERE domain_in_ip = 1
   OR qty_nameservers = 0
   OR qty_dot_domain > 3;