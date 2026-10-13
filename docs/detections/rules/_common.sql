-- Shared macros for the rule files. `.read` this first.
CREATE OR REPLACE MACRO is_internal(ip) AS
    regexp_matches(ip, '^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|100\.(6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.|169\.254\.|fe80:|f[cd]|ff|22[4-9]\.|23[0-9]\.|255\.255\.255\.255)');
CREATE OR REPLACE MACRO base_domain(n) AS
    -- last two labels; replace with a Public Suffix List lookup in tapwatch
    array_to_string(list_slice(string_split(lower(rtrim(n, '.')), '.'), -2, -1), '.');
CREATE OR REPLACE MACRO zeek(log) AS getvariable('zeek') || '/' || log || '*.log*';
CREATE OR REPLACE VIEW conn AS SELECT * FROM read_json_auto(zeek('conn'), format='newline_delimited', ignore_errors=true);
CREATE OR REPLACE VIEW dns  AS SELECT * FROM read_json_auto(zeek('dns'),  format='newline_delimited', ignore_errors=true);
CREATE OR REPLACE VIEW ssl  AS SELECT * FROM read_json_auto(zeek('ssl'),  format='newline_delimited', ignore_errors=true);
CREATE OR REPLACE VIEW dhcp AS SELECT * FROM read_json_auto(zeek('dhcp'), format='newline_delimited', ignore_errors=true);
-- assets.yaml exported as CSV: ip, mac, name, role, fixed_function (bool), admin (bool)
CREATE OR REPLACE VIEW assets AS SELECT * FROM read_csv_auto(getvariable('assets'));
