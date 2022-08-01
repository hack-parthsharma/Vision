# Vision

This script analyses the Nmap XML scanning results, parses each CPE context and correlates to search CVE on NIST. You can use that to find public vulnerabilities in services.

```
	..::: VISION v0.3 :::... 
        Nmap\'s XML result parser and NVD's CPE correlation to search CVE
	
	Example:
		python Vision-cpe.py result_scan.xml 3 txt
	argv 1 = Nmap scanner results in XML
	argv 2 = Limit CVEs per CPE to get
	argv 3 = Type of output (xml or txt)
	
To install modules:
$ sudo python3 -m pip install -r requirements.txt
```

## Example of results:
```
$ sudo nmap -sS -sV -O -P0 02:42:0A:00:00:03 -oX result.xml
$ python3 Vision-cpe.py result.xml 3 txt

::::: Vision v0.3 - nmap NVD's cpe correlation with CVE - Coded by CoolerVoid

Find CPE : vsftpd vsftpd 2.3.4
Host: 02:42:0A:00:00:03
Port: 21
vsftpd vsftpd 2.3.4

	URL: https://nvd.nist.gov/vuln/detail/CVE-2011-2523
	Description: vsftpd 2.3.4 downloaded between 20110630 and 20110703 contains a backdoor which opens a shell on port 6200/tcp.

	Risk cvss-3: 9.8 CRITICAL

	Risk cvss-2: 10.0 HIGH

	URL: https://nvd.nist.gov/vuln/detail/CVE-2011-0762
	Description: The vsf_filename_passes_filter function in ls.c in vsftpd before 2.3.3 allows remote authenticated users to cause a denial of service (CPU consumption and process slot exhaustion) via crafted glob expressions in STAT commands in multiple FTP sessions, a different vulnerability than CVE-2010-2632.

	Risk cvss-2: 4.0 MEDIUM

Find CPE : openbsd openssh 4.7p1
Host: 02:42:0A:00:00:03
Port: 22
openbsd openssh 4.7p1

Find CPE : apache http_server 2.2.8
Host: 02:42:0A:00:00:03
Port: 80
apache http_server 2.2.8

Find CPE : proftpd proftpd 1.3.1
Host: 02:42:0A:00:00:03
Port: 2121
proftpd proftpd 1.3.1

	URL: https://nvd.nist.gov/vuln/detail/CVE-2009-0543
	Description: ProFTPD Server 1.3.1, with NLS support enabled, allows remote attackers to bypass SQL injection protection mechanisms via invalid, encoded multibyte characters, which are not properly handled in (1) mod_sql_mysql and (2) mod_sql_postgres.

	Risk cvss-2: 6.8 MEDIUM

	URL: https://nvd.nist.gov/vuln/detail/CVE-2009-0542
	Description: SQL injection vulnerability in ProFTPD Server 1.3.1 through 1.3.2rc2 allows remote attackers to execute arbitrary SQL commands via a &quot;%&quot; (percent) character in the username, which introduces a &quot;&#39;&quot; (single quote) character during variable substitution by mod_sql.

	Risk cvss-2: 7.5 HIGH

	URL: https://nvd.nist.gov/vuln/detail/CVE-2008-4242
	Description: ProFTPD 1.3.1 interprets long commands from an FTP client as multiple commands, which allows remote attackers to conduct cross-site request forgery (CSRF) attacks and execute arbitrary FTP commands via a long ftp:// URI that leverages an existing session from the FTP client implementation in a web browser.

	Risk cvss-2: 6.8 MEDIUM

	URL: https://nvd.nist.gov/vuln/detail/CVE-2006-6563
	Description: Stack-based buffer overflow in the pr_ctrls_recv_request function in ctrls.c in the mod_ctrls module in ProFTPD before 1.3.1rc1 allows local users to execute arbitrary code via a large reqarglen length value.

	Risk cvss-2: 6.6 MEDIUM

Find CPE : mysql mysql 5.0.51a
Host: 02:42:0A:00:00:03
Port: 3306
mysql mysql 5.0.51a

	URL: https://nvd.nist.gov/vuln/detail/CVE-2009-4484
	Description: Multiple stack-based buffer overflows in the CertDecoder::GetName function in src/asn.cpp in TaoCrypt in yaSSL before 1.9.9, as used in mysqld in MySQL 5.0.x before 5.0.90, MySQL 5.1.x before 5.1.43, MySQL 5.5.x through 5.5.0-m2, and other products, allow remote attackers to execute arbitrary code or cause a denial of service (memory corruption and daemon crash) by establishing an SSL connection and sending an X.509 client certificate with a crafted name field, as demonstrated by mysql_overflow1.py and the vd_mysql5 module in VulnDisco Pack Professional 8.11. NOTE: this was originally reported for MySQL 5.0.51a.

	Risk cvss-2: 7.5 HIGH

	URL: https://nvd.nist.gov/vuln/detail/CVE-2008-4097
	Description: MySQL 5.0.51a allows local users to bypass certain privilege checks by calling CREATE TABLE on a MyISAM table with modified (1) DATA DIRECTORY or (2) INDEX DIRECTORY arguments that are associated with symlinks within pathnames for subdirectories of the MySQL home data directory, which are followed when tables are created in the future. NOTE: this vulnerability exists because of an incomplete fix for CVE-2008-2079.

	Risk cvss-2: 4.6 MEDIUM

	URL: https://nvd.nist.gov/vuln/detail/CVE-2007-6303
	Description: MySQL 5.0.x before 5.0.51a, 5.1.x before 5.1.23, and 6.0.x before 6.0.4 does not update the DEFINER value of a view when the view is altered, which allows remote authenticated users to gain privileges via a sequence of statements including a CREATE SQL SECURITY DEFINER VIEW statement and an ALTER VIEW statement.

	Risk cvss-2: 3.5 LOW

	URL: https://nvd.nist.gov/vuln/detail/CVE-2007-6304
	Description: The federated engine in MySQL 5.0.x before 5.0.51a, 5.1.x before 5.1.23, and 6.0.x before 6.0.4, when performing a certain SHOW TABLE STATUS query, allows remote MySQL servers to cause a denial of service (federated handler crash and daemon crash) via a response that lacks the minimum required number of columns.

	Risk cvss-2: 5.0 MEDIUM

Find CPE : postgresql postgresql 8.3
Host: 02:42:0A:00:00:03
Port: 5432
postgresql postgresql 8.3

	URL: https://nvd.nist.gov/vuln/detail/CVE-2013-1903
	Description: PostgreSQL, possibly 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 incorrectly provides the superuser password to scripts related to &quot;graphical installers for Linux and Mac OS X,&quot; which has unspecified impact and attack vectors.

	Risk cvss-2: 10.0 HIGH

	URL: https://nvd.nist.gov/vuln/detail/CVE-2013-1902
	Description: PostgreSQL, 9.2.x before 9.2.4, 9.1.x before 9.1.9, 9.0.x before 9.0.13, 8.4.x before 8.4.17, and 8.3.x before 8.3.23 generates insecure temporary files with predictable filenames, which has unspecified impact and attack vectors related to &quot;graphical installers for Linux and Mac OS X.&quot;

	Risk cvss-2: 10.0 HIGH

	URL: https://nvd.nist.gov/vuln/detail/CVE-2013-0255
	Description: PostgreSQL 9.2.x before 9.2.3, 9.1.x before 9.1.8, 9.0.x before 9.0.12, 8.4.x before 8.4.16, and 8.3.x before 8.3.23 does not properly declare the enum_recv function in backend/utils/adt/enum.c, which causes it to be invoked with incorrect arguments and allows remote authenticated users to cause a denial of service (server crash) or read sensitive process memory via a crafted SQL command, which triggers an array index error and an out-of-bounds read.

	Risk cvss-2: 6.8 MEDIUM

	URL: https://nvd.nist.gov/vuln/detail/CVE-2012-3489
	Description: The xml_parse function in the libxml2 support in the core server component in PostgreSQL 8.3 before 8.3.20, 8.4 before 8.4.13, 9.0 before 9.0.9, and 9.1 before 9.1.5 allows remote authenticated users to determine the existence of arbitrary files or URLs, and possibly obtain file or URL content that triggers a parsing error, via an XML value that refers to (1) a DTD or (2) an entity, related to an XML External Entity (aka XXE) issue.

	Risk cvss-2: 4.0 MEDIUM

Find CPE : apache coyote_http_connector 1.1
Host: 02:42:0A:00:00:03
Port: 8180
apache coyote_http_connector 1.1

Start parser

```

## Common questions:

## How to write XML output on Nmap ?
https://nmap.org/book/output-formats-xml-output.html

## What is a CPE  ?

https://nmap.org/book/output-formats-cpe.html

https://nvd.nist.gov/products/cpe

## What is a CVE ?

https://cve.mitre.org/


## This is a true vulnerability scanner ?

Nop, this script is util to audit banners of services, this tool don't test inputs... Full vulnerability scanner its complex, look that following http://www.openvas.org/


## Author: Parth Sharma

