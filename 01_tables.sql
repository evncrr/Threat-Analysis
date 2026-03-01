CREATE DATABASE IF NOT EXISTS cyber_threat_intelligence;
USE cyber_threat_intelligence;

SET GLOBAL local_infile = 1;

USE cyber_threat_intelligence;

-- NETWORK TRAFFIC TABLE

DROP TABLE IF EXISTS network_traffic;

CREATE TABLE network_traffic (
    id                  INT,
    dur                 DOUBLE,
    proto               VARCHAR(20),
    service             VARCHAR(20),
    state               VARCHAR(10),

    spkts               INT,
    dpkts               INT,

    sbytes              BIGINT,
    dbytes              BIGINT,

    rate                DOUBLE,
    sttl                INT,
    dttl                INT,

    sload               DOUBLE,
    dload               DOUBLE,

    sloss               INT,
    dloss               INT,

    sinpkt              DOUBLE,
    dinpkt              DOUBLE,

    sjit                DOUBLE,
    djit                DOUBLE,

    swin                INT,
    stcpb               BIGINT,
    dtcpb               BIGINT,
    dwin                INT,

    tcprtt              DOUBLE,
    synack              DOUBLE,
    ackdat              DOUBLE,

    smean               INT,
    dmean               INT,

    trans_depth         INT,
    response_body_len   INT,

    ct_srv_src          INT,
    ct_state_ttl        INT,
    ct_dst_ltm          INT,
    ct_src_dport_ltm    INT,
    ct_dst_sport_ltm    INT,
    ct_dst_src_ltm      INT,

    is_ftp_login        INT,
    ct_ftp_cmd          INT,
    ct_flw_http_mthd    INT,

    ct_src_ltm          INT,
    ct_srv_dst          INT,
    is_sm_ips_ports     INT,

    attack_cat          VARCHAR(50),
    label               INT
);

CREATE INDEX idx_net_attack  ON network_traffic(attack_cat);
CREATE INDEX idx_net_proto   ON network_traffic(proto);
CREATE INDEX idx_net_label   ON network_traffic(label);

-- PHISHING URLS TABLE

DROP TABLE IF EXISTS phishing_urls;

CREATE TABLE phishing_urls (

    qty_dot_url                 INT,
    qty_hyphen_url              INT,
    qty_underline_url           INT,
    qty_slash_url               INT,
    qty_questionmark_url        INT,
    qty_equal_url               INT,
    qty_at_url                  INT,
    qty_and_url                 INT,
    qty_exclamation_url         INT,
    qty_space_url               INT,
    qty_tilde_url               INT,
    qty_comma_url               INT,
    qty_plus_url                INT,
    qty_asterisk_url            INT,
    qty_hashtag_url             INT,
    qty_dollar_url              INT,
    qty_percent_url             INT,
    qty_tld_url                 INT,
    length_url                  INT,

    qty_dot_domain              INT,
    qty_hyphen_domain           INT,
    qty_underline_domain        INT,
    qty_slash_domain            INT,
    qty_questionmark_domain     INT,
    qty_equal_domain            INT,
    qty_at_domain               INT,
    qty_and_domain              INT,
    qty_exclamation_domain      INT,
    qty_space_domain            INT,
    qty_tilde_domain            INT,
    qty_comma_domain            INT,
    qty_plus_domain             INT,
    qty_asterisk_domain         INT,
    qty_hashtag_domain          INT,
    qty_dollar_domain           INT,
    qty_percent_domain          INT,
    qty_vowels_domain           INT,
    domain_length               INT,
    domain_in_ip                INT,
    server_client_domain        INT,

    qty_dot_directory           INT,
    qty_hyphen_directory        INT,
    qty_underline_directory     INT,
    qty_slash_directory         INT,
    qty_questionmark_directory  INT,
    qty_equal_directory         INT,
    qty_at_directory            INT,
    qty_and_directory           INT,
    qty_exclamation_directory   INT,
    qty_space_directory         INT,
    qty_tilde_directory         INT,
    qty_comma_directory         INT,
    qty_plus_directory          INT,
    qty_asterisk_directory      INT,
    qty_hashtag_directory       INT,
    qty_dollar_directory        INT,
    qty_percent_directory       INT,
    directory_length            INT,

    qty_dot_file                INT,
    qty_hyphen_file             INT,
    qty_underline_file          INT,
    qty_slash_file              INT,
    qty_questionmark_file       INT,
    qty_equal_file              INT,
    qty_at_file                 INT,
    qty_and_file                INT,
    qty_exclamation_file        INT,
    qty_space_file              INT,
    qty_tilde_file              INT,
    qty_comma_file              INT,
    qty_plus_file               INT,
    qty_asterisk_file           INT,
    qty_hashtag_file            INT,
    qty_dollar_file             INT,
    qty_percent_file            INT,
    file_length                 INT,

    qty_dot_params              INT,
    qty_hyphen_params           INT,
    qty_underline_params        INT,
    qty_slash_params            INT,
    qty_questionmark_params     INT,
    qty_equal_params            INT,
    qty_at_params               INT,
    qty_and_params              INT,
    qty_exclamation_params      INT,
    qty_space_params            INT,
    qty_tilde_params            INT,
    qty_comma_params            INT,
    qty_plus_params             INT,
    qty_asterisk_params         INT,
    qty_hashtag_params          INT,
    qty_dollar_params           INT,
    qty_percent_params          INT,
    params_length               INT,
    tld_present_params          INT,
    qty_params                  INT,

    email_in_url                INT,
    time_response               DOUBLE,
    domain_spf                  INT,
    asn_ip                      INT,
    time_domain_activation      INT,
    time_domain_expiration      INT,
    qty_ip_resolved             INT,
    qty_nameservers             INT,
    qty_mx_servers              INT,
    ttl_hostname                INT,
    tls_ssl_certificate         INT,
    qty_redirects               INT,
    url_google_index            INT,
    domain_google_index         INT,
    url_shortened               INT,

    phishing                    INT
);

CREATE INDEX idx_phish_label ON phishing_urls(phishing);
CREATE INDEX idx_phish_tls   ON phishing_urls(tls_ssl_certificate);