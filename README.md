# DockerBuild方法についての追記

```
mvn package jib:dockerBuild
docker run -d -p 8080:8080 -v $PWD/h2:/usr/local/tomcat/h2 --name myapp-container-jaxrs myapp-container-jaxrs

curl localhost:8080/find/json

```


# ディレクトリについての補足

| ディレクトリ               | 補足                                                                                                                                                                             |
|:---------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
|db/data/                    |DBに疎通確認用データを格納するためのSQL文。                                                                                                                                       |
|db/ddl/                     |Nablarchで使用するテーブルを作成するためのDDL。テーブルを作り直すときに使用するDROP文も用意している。                                                                             |
|h2/bin/                     |H2 Database Engine(以下H2)に格納されているデータを確認するためのツールが格納されている(本プロジェクトは初期状態でH2を使用する構成になっている)。                                  |
|h2/db/                      |H2のデータファイルが格納されているディレクトリ。H2のデータが壊れた際は、「SAMPLE.mv.db」を削除し、「SAMPLE.mv.db.org」を、「SAMPLE.mv.db」という名前でコピーすることで復旧できる。|
|src/main/resources/         |設定ファイルを格納するディレクトリ                                                                                                                                                |
|src/test/resources/         |自動テスト(ユニットテスト)用の設定ファイルを格納するディレクトリ                                                                                                                  |
|src/main/jib/               |Dockerコンテナに直接配置するファイルを格納するディレクトリ(詳細は[Jibのドキュメント](https://github.com/GoogleContainerTools/jib/tree/master/jib-maven-plugin#adding-arbitrary-files-to-the-image)を参照)|
|tools/                      |mavenと連携して動作させるツールの設定を格納するディレクトリ                                                                                                                       |


# H2に格納されているデータを確認する方法

以下の手順で確認する。

1.「mvn waitt:run」でアプリを起動している場合は終了させる。

2.h2/bin/h2.batを実行する。

3.しばらく待つとブラウザが起動するので、各項目に以下の通りに入力し、[Connect]ボタンをクリックする。

| 項目     | 値                  |
|:---------|:--------------------|
|JDBC URL  |jdbc:h2:../db/SAMPLE |
|User Name |SAMPLE               |
|Password  |SAMPLE               |

4.左側のペインのテーブル名をクリックすると、クリックしたテーブルに対するSELECT文が生成される。

5.[Run]ボタンをクリックすると、生成したSELECT文が実行され、テーブルのデータを確認することができる。

6.使用終了時は、左上のdisconnectボタン(赤色で書かれたアイコンのボタン)をクリックして切断する。
  **切断を忘れると、WebアプリからH2に接続できなくなる。**

## trivy scan result.

```

2022-03-08T20:10:51.734+0900	[34mINFO[0m	Detected OS: ubuntu
2022-03-08T20:10:51.734+0900	[34mINFO[0m	Detecting Ubuntu vulnerabilities...
2022-03-08T20:10:51.741+0900	[34mINFO[0m	Number of language-specific files: 1
2022-03-08T20:10:51.741+0900	[34mINFO[0m	Detecting jar vulnerabilities...

myapp-container-jaxrs:0.1.0 (ubuntu 18.04)
==========================================
Total: 251 (UNKNOWN: 0, LOW: 133, MEDIUM: 105, HIGH: 13, CRITICAL: 0)

+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
|       LIBRARY        | VULNERABILITY ID | SEVERITY |          INSTALLED VERSION          |            FIXED VERSION            |                     TITLE                      |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| apt                  | CVE-2020-27350   | MEDIUM   | 1.6.12ubuntu0.1                     | 1.6.12ubuntu0.2                     | apt: integer overflows and underflows          |
|                      |                  |          |                                     |                                     | while parsing .deb packages                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-27350          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| bash                 | CVE-2019-18276   | LOW      | 4.4.18-2ubuntu1.2                   |                                     | bash: when effective UID is not                |
|                      |                  |          |                                     |                                     | equal to its real UID the...                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-18276          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| bsdutils             | CVE-2018-7738    |          | 2.31.1-0.4ubuntu3.6                 | 2.31.1-0.4ubuntu3.7                 | util-linux: Shell command                      |
|                      |                  |          |                                     |                                     | injection in unescaped                         |
|                      |                  |          |                                     |                                     | bash-completed mount point names               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7738           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| coreutils            | CVE-2016-2781    |          | 8.28-1ubuntu1                       |                                     | coreutils: Non-privileged                      |
|                      |                  |          |                                     |                                     | session can escape to the                      |
|                      |                  |          |                                     |                                     | parent session in chroot                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2016-2781           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| curl                 | CVE-2020-8177    | MEDIUM   | 7.58.0-2ubuntu3.8                   | 7.58.0-2ubuntu3.9                   | curl: Incorrect argument                       |
|                      |                  |          |                                     |                                     | check can allow remote servers                 |
|                      |                  |          |                                     |                                     | to overwrite local files...                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8177           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-8285    |          |                                     | 7.58.0-2ubuntu3.12                  | curl: Malicious FTP server can                 |
|                      |                  |          |                                     |                                     | trigger stack overflow when                    |
|                      |                  |          |                                     |                                     | CURLOPT_CHUNK_BGN_FUNCTION                     |
|                      |                  |          |                                     |                                     | is used...                                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8285           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-8286    |          |                                     |                                     | curl: Inferior OCSP verification               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8286           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-22876   |          |                                     | 7.58.0-2ubuntu3.13                  | curl: Leak of authentication                   |
|                      |                  |          |                                     |                                     | credentials in URL                             |
|                      |                  |          |                                     |                                     | via automatic Referer                          |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22876          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-22924   |          |                                     | 7.58.0-2ubuntu3.14                  | curl: Bad connection reuse                     |
|                      |                  |          |                                     |                                     | due to flawed path name checks                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22924          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-22925   |          |                                     |                                     | curl: Incorrect fix for                        |
|                      |                  |          |                                     |                                     | CVE-2021-22898 TELNET                          |
|                      |                  |          |                                     |                                     | stack contents disclosure                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22925          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-22946   |          |                                     | 7.58.0-2ubuntu3.15                  | curl: Requirement to use                       |
|                      |                  |          |                                     |                                     | TLS not properly enforced                      |
|                      |                  |          |                                     |                                     | for IMAP, POP3, and...                         |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22946          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-22947   |          |                                     |                                     | curl: Server responses                         |
|                      |                  |          |                                     |                                     | received before STARTTLS                       |
|                      |                  |          |                                     |                                     | processed after TLS handshake                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22947          |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-8231    | LOW      |                                     | 7.58.0-2ubuntu3.10                  | curl: Expired pointer                          |
|                      |                  |          |                                     |                                     | dereference via multi API with                 |
|                      |                  |          |                                     |                                     | CURLOPT_CONNECT_ONLY option set                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8231           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-8284    |          |                                     | 7.58.0-2ubuntu3.12                  | curl: FTP PASV command                         |
|                      |                  |          |                                     |                                     | response can cause curl                        |
|                      |                  |          |                                     |                                     | to connect to arbitrary...                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8284           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-22898   |          |                                     | 7.58.0-2ubuntu3.14                  | curl: TELNET stack                             |
|                      |                  |          |                                     |                                     | contents disclosure                            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22898          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| fdisk                | CVE-2018-7738    |          | 2.31.1-0.4ubuntu3.6                 | 2.31.1-0.4ubuntu3.7                 | util-linux: Shell command                      |
|                      |                  |          |                                     |                                     | injection in unescaped                         |
|                      |                  |          |                                     |                                     | bash-completed mount point names               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7738           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| gcc-8-base           | CVE-2020-13844   | MEDIUM   | 8.4.0-1ubuntu1~18.04                |                                     | kernel: ARM straight-line                      |
|                      |                  |          |                                     |                                     | speculation vulnerability                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-13844          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| gpgv                 | CVE-2019-13050   | LOW      | 2.2.4-1ubuntu1.2                    |                                     | GnuPG: interaction between the                 |
|                      |                  |          |                                     |                                     | sks-keyserver code and GnuPG                   |
|                      |                  |          |                                     |                                     | allows for a Certificate...                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-13050          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-14855   |          |                                     | 2.2.4-1ubuntu1.3                    | gnupg2: OpenPGP Key Certification              |
|                      |                  |          |                                     |                                     | Forgeries with SHA-1                           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-14855          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libapt-pkg5.0        | CVE-2020-27350   | MEDIUM   | 1.6.12ubuntu0.1                     | 1.6.12ubuntu0.2                     | apt: integer overflows and underflows          |
|                      |                  |          |                                     |                                     | while parsing .deb packages                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-27350          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libasn1-8-heimdal    | CVE-2019-12098   | LOW      | 7.5.0+dfsg-1                        |                                     | In the client side of Heimdal before           |
|                      |                  |          |                                     |                                     | 7.6.0, failure to verify anonymou...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-12098          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3671    |          |                                     |                                     | samba: Null pointer dereference                |
|                      |                  |          |                                     |                                     | on missing sname in TGS-REQ                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3671           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libblkid1            | CVE-2018-7738    |          | 2.31.1-0.4ubuntu3.6                 | 2.31.1-0.4ubuntu3.7                 | util-linux: Shell command                      |
|                      |                  |          |                                     |                                     | injection in unescaped                         |
|                      |                  |          |                                     |                                     | bash-completed mount point names               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7738           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libc-bin             | CVE-2018-11236   | MEDIUM   | 2.27-3ubuntu1                       | 2.27-3ubuntu1.2                     | glibc: Integer overflow in                     |
|                      |                  |          |                                     |                                     | stdlib/canonicalize.c on                       |
|                      |                  |          |                                     |                                     | 32-bit architectures leading                   |
|                      |                  |          |                                     |                                     | to stack-based buffer...                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-11236          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2018-11237   |          |                                     |                                     | glibc: Buffer overflow in                      |
|                      |                  |          |                                     |                                     | __mempcpy_avx512_no_vzeroupper                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-11237          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2018-19591   |          |                                     |                                     | glibc: file descriptor                         |
|                      |                  |          |                                     |                                     | leak in if_nametoindex() in                    |
|                      |                  |          |                                     |                                     | sysdeps/unix/sysv/linux/if_index.c             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-19591          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-1751    |          |                                     |                                     | glibc: array overflow in                       |
|                      |                  |          |                                     |                                     | backtrace functions for powerpc                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-1751           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3999    |          |                                     | 2.27-3ubuntu1.5                     | glibc: Off-by-one buffer                       |
|                      |                  |          |                                     |                                     | overflow/underflow in getcwd()                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3999           |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2009-5155    | LOW      |                                     |                                     | glibc: parse_reg_exp in                        |
|                      |                  |          |                                     |                                     | posix/regcomp.c misparses                      |
|                      |                  |          |                                     |                                     | alternatives leading to                        |
|                      |                  |          |                                     |                                     | denial of service or...                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2009-5155           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2015-8985    |          |                                     |                                     | glibc: potential denial of                     |
|                      |                  |          |                                     |                                     | service in pop_fail_stack()                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2015-8985           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2016-10228   |          |                                     | 2.27-3ubuntu1.5                     | glibc: iconv program can hang                  |
|                      |                  |          |                                     |                                     | when invoked with the -c option                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2016-10228          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2016-10739   |          |                                     |                                     | glibc: getaddrinfo should reject IP            |
|                      |                  |          |                                     |                                     | addresses with trailing characters             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2016-10739          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-19126   |          |                                     | 2.27-3ubuntu1.2                     | glibc: LD_PREFER_MAP_32BIT_EXEC                |
|                      |                  |          |                                     |                                     | not ignored in setuid binaries                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-19126          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-25013   |          |                                     | 2.27-3ubuntu1.5                     | glibc: buffer over-read in                     |
|                      |                  |          |                                     |                                     | iconv when processing invalid                  |
|                      |                  |          |                                     |                                     | multi-byte input sequences in...               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-25013          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-9169    |          |                                     | 2.27-3ubuntu1.2                     | glibc: regular-expression                      |
|                      |                  |          |                                     |                                     | match via proceed_next_node                    |
|                      |                  |          |                                     |                                     | in posix/regexec.c leads to                    |
|                      |                  |          |                                     |                                     | heap-based buffer over-read...                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-9169           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-10029   |          |                                     |                                     | glibc: stack corruption                        |
|                      |                  |          |                                     |                                     | from crafted input in cosl,                    |
|                      |                  |          |                                     |                                     | sinl, sincosl, and tanl...                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-10029          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-1752    |          |                                     |                                     | glibc: use-after-free in glob()                |
|                      |                  |          |                                     |                                     | function when expanding ~user                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-1752           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-27618   |          |                                     | 2.27-3ubuntu1.5                     | glibc: iconv when processing                   |
|                      |                  |          |                                     |                                     | invalid multi-byte input                       |
|                      |                  |          |                                     |                                     | sequences fails to advance the...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-27618          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-29562   |          |                                     |                                     | glibc: assertion failure in iconv              |
|                      |                  |          |                                     |                                     | when converting invalid UCS4                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-29562          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-6096    |          |                                     |                                     | glibc: signed comparison                       |
|                      |                  |          |                                     |                                     | vulnerability in the                           |
|                      |                  |          |                                     |                                     | ARMv7 memcpy function                          |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-6096           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-3326    |          |                                     |                                     | glibc: Assertion failure in                    |
|                      |                  |          |                                     |                                     | ISO-2022-JP-3 gconv module                     |
|                      |                  |          |                                     |                                     | related to combining characters                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3326           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-35942   |          |                                     |                                     | glibc: Arbitrary read in wordexp()             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-35942          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-23218   |          |                                     |                                     | glibc: Stack-based buffer overflow             |
|                      |                  |          |                                     |                                     | in svcunix_create via long pathnames           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-23218          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-23219   |          |                                     |                                     | glibc: Stack-based buffer                      |
|                      |                  |          |                                     |                                     | overflow in sunrpc clnt_create                 |
|                      |                  |          |                                     |                                     | via a long pathname                            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-23219          |
+----------------------+------------------+----------+                                     +-------------------------------------+------------------------------------------------+
| libc6                | CVE-2018-11236   | MEDIUM   |                                     | 2.27-3ubuntu1.2                     | glibc: Integer overflow in                     |
|                      |                  |          |                                     |                                     | stdlib/canonicalize.c on                       |
|                      |                  |          |                                     |                                     | 32-bit architectures leading                   |
|                      |                  |          |                                     |                                     | to stack-based buffer...                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-11236          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2018-11237   |          |                                     |                                     | glibc: Buffer overflow in                      |
|                      |                  |          |                                     |                                     | __mempcpy_avx512_no_vzeroupper                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-11237          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2018-19591   |          |                                     |                                     | glibc: file descriptor                         |
|                      |                  |          |                                     |                                     | leak in if_nametoindex() in                    |
|                      |                  |          |                                     |                                     | sysdeps/unix/sysv/linux/if_index.c             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-19591          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-1751    |          |                                     |                                     | glibc: array overflow in                       |
|                      |                  |          |                                     |                                     | backtrace functions for powerpc                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-1751           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3999    |          |                                     | 2.27-3ubuntu1.5                     | glibc: Off-by-one buffer                       |
|                      |                  |          |                                     |                                     | overflow/underflow in getcwd()                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3999           |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2009-5155    | LOW      |                                     |                                     | glibc: parse_reg_exp in                        |
|                      |                  |          |                                     |                                     | posix/regcomp.c misparses                      |
|                      |                  |          |                                     |                                     | alternatives leading to                        |
|                      |                  |          |                                     |                                     | denial of service or...                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2009-5155           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2015-8985    |          |                                     |                                     | glibc: potential denial of                     |
|                      |                  |          |                                     |                                     | service in pop_fail_stack()                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2015-8985           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2016-10228   |          |                                     | 2.27-3ubuntu1.5                     | glibc: iconv program can hang                  |
|                      |                  |          |                                     |                                     | when invoked with the -c option                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2016-10228          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2016-10739   |          |                                     |                                     | glibc: getaddrinfo should reject IP            |
|                      |                  |          |                                     |                                     | addresses with trailing characters             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2016-10739          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-19126   |          |                                     | 2.27-3ubuntu1.2                     | glibc: LD_PREFER_MAP_32BIT_EXEC                |
|                      |                  |          |                                     |                                     | not ignored in setuid binaries                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-19126          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-25013   |          |                                     | 2.27-3ubuntu1.5                     | glibc: buffer over-read in                     |
|                      |                  |          |                                     |                                     | iconv when processing invalid                  |
|                      |                  |          |                                     |                                     | multi-byte input sequences in...               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-25013          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-9169    |          |                                     | 2.27-3ubuntu1.2                     | glibc: regular-expression                      |
|                      |                  |          |                                     |                                     | match via proceed_next_node                    |
|                      |                  |          |                                     |                                     | in posix/regexec.c leads to                    |
|                      |                  |          |                                     |                                     | heap-based buffer over-read...                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-9169           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-10029   |          |                                     |                                     | glibc: stack corruption                        |
|                      |                  |          |                                     |                                     | from crafted input in cosl,                    |
|                      |                  |          |                                     |                                     | sinl, sincosl, and tanl...                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-10029          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-1752    |          |                                     |                                     | glibc: use-after-free in glob()                |
|                      |                  |          |                                     |                                     | function when expanding ~user                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-1752           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-27618   |          |                                     | 2.27-3ubuntu1.5                     | glibc: iconv when processing                   |
|                      |                  |          |                                     |                                     | invalid multi-byte input                       |
|                      |                  |          |                                     |                                     | sequences fails to advance the...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-27618          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-29562   |          |                                     |                                     | glibc: assertion failure in iconv              |
|                      |                  |          |                                     |                                     | when converting invalid UCS4                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-29562          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-6096    |          |                                     |                                     | glibc: signed comparison                       |
|                      |                  |          |                                     |                                     | vulnerability in the                           |
|                      |                  |          |                                     |                                     | ARMv7 memcpy function                          |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-6096           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-3326    |          |                                     |                                     | glibc: Assertion failure in                    |
|                      |                  |          |                                     |                                     | ISO-2022-JP-3 gconv module                     |
|                      |                  |          |                                     |                                     | related to combining characters                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3326           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-35942   |          |                                     |                                     | glibc: Arbitrary read in wordexp()             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-35942          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-23218   |          |                                     |                                     | glibc: Stack-based buffer overflow             |
|                      |                  |          |                                     |                                     | in svcunix_create via long pathnames           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-23218          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-23219   |          |                                     |                                     | glibc: Stack-based buffer                      |
|                      |                  |          |                                     |                                     | overflow in sunrpc clnt_create                 |
|                      |                  |          |                                     |                                     | via a long pathname                            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-23219          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libcurl4             | CVE-2020-8177    | MEDIUM   | 7.58.0-2ubuntu3.8                   | 7.58.0-2ubuntu3.9                   | curl: Incorrect argument                       |
|                      |                  |          |                                     |                                     | check can allow remote servers                 |
|                      |                  |          |                                     |                                     | to overwrite local files...                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8177           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-8285    |          |                                     | 7.58.0-2ubuntu3.12                  | curl: Malicious FTP server can                 |
|                      |                  |          |                                     |                                     | trigger stack overflow when                    |
|                      |                  |          |                                     |                                     | CURLOPT_CHUNK_BGN_FUNCTION                     |
|                      |                  |          |                                     |                                     | is used...                                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8285           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-8286    |          |                                     |                                     | curl: Inferior OCSP verification               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8286           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-22876   |          |                                     | 7.58.0-2ubuntu3.13                  | curl: Leak of authentication                   |
|                      |                  |          |                                     |                                     | credentials in URL                             |
|                      |                  |          |                                     |                                     | via automatic Referer                          |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22876          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-22924   |          |                                     | 7.58.0-2ubuntu3.14                  | curl: Bad connection reuse                     |
|                      |                  |          |                                     |                                     | due to flawed path name checks                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22924          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-22925   |          |                                     |                                     | curl: Incorrect fix for                        |
|                      |                  |          |                                     |                                     | CVE-2021-22898 TELNET                          |
|                      |                  |          |                                     |                                     | stack contents disclosure                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22925          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-22946   |          |                                     | 7.58.0-2ubuntu3.15                  | curl: Requirement to use                       |
|                      |                  |          |                                     |                                     | TLS not properly enforced                      |
|                      |                  |          |                                     |                                     | for IMAP, POP3, and...                         |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22946          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-22947   |          |                                     |                                     | curl: Server responses                         |
|                      |                  |          |                                     |                                     | received before STARTTLS                       |
|                      |                  |          |                                     |                                     | processed after TLS handshake                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22947          |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-8231    | LOW      |                                     | 7.58.0-2ubuntu3.10                  | curl: Expired pointer                          |
|                      |                  |          |                                     |                                     | dereference via multi API with                 |
|                      |                  |          |                                     |                                     | CURLOPT_CONNECT_ONLY option set                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8231           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-8284    |          |                                     | 7.58.0-2ubuntu3.12                  | curl: FTP PASV command                         |
|                      |                  |          |                                     |                                     | response can cause curl                        |
|                      |                  |          |                                     |                                     | to connect to arbitrary...                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-8284           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-22898   |          |                                     | 7.58.0-2ubuntu3.14                  | curl: TELNET stack                             |
|                      |                  |          |                                     |                                     | contents disclosure                            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-22898          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libexpat1            | CVE-2022-25235   | HIGH     | 2.2.5-3ubuntu0.2                    | 2.2.5-3ubuntu0.4                    | expat: malformed 2- and                        |
|                      |                  |          |                                     |                                     | 3-byte UTF-8 sequences can                     |
|                      |                  |          |                                     |                                     | lead to arbitrary code...                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-25235          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-25236   |          |                                     |                                     | expat: namespace-separator characters          |
|                      |                  |          |                                     |                                     | in "xmlns[:prefix]" attribute                  |
|                      |                  |          |                                     |                                     | values can lead to arbitrary code...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-25236          |
+                      +------------------+----------+                                     +                                     +------------------------------------------------+
|                      | CVE-2021-46143   | MEDIUM   |                                     |                                     | expat: Integer overflow                        |
|                      |                  |          |                                     |                                     | in doProlog in xmlparse.c                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-46143          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-22822   |          |                                     |                                     | expat: Integer overflow in                     |
|                      |                  |          |                                     |                                     | addBinding in xmlparse.c                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-22822          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-22823   |          |                                     |                                     | expat: Integer overflow in                     |
|                      |                  |          |                                     |                                     | build_model in xmlparse.c                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-22823          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-22824   |          |                                     |                                     | expat: Integer overflow in                     |
|                      |                  |          |                                     |                                     | defineAttribute in xmlparse.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-22824          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-22825   |          |                                     |                                     | expat: Integer overflow                        |
|                      |                  |          |                                     |                                     | in lookup in xmlparse.c                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-22825          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-22826   |          |                                     |                                     | expat: Integer overflow in                     |
|                      |                  |          |                                     |                                     | nextScaffoldPart in xmlparse.c                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-22826          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-22827   |          |                                     |                                     | expat: Integer overflow                        |
|                      |                  |          |                                     |                                     | in storeAtts in xmlparse.c                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-22827          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-23852   |          |                                     |                                     | expat: integer overflow                        |
|                      |                  |          |                                     |                                     | in function XML_GetBuffer                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-23852          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-23990   |          |                                     |                                     | expat: integer overflow                        |
|                      |                  |          |                                     |                                     | in the doProlog function                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-23990          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2022-25314   |          |                                     |                                     | expat: integer overflow                        |
|                      |                  |          |                                     |                                     | in copyString()                                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-25314          |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-45960   | LOW      |                                     | 2.2.5-3ubuntu0.4                    | expat: Large number of prefixed XML            |
|                      |                  |          |                                     |                                     | attributes on a single tag can...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-45960          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libfdisk1            | CVE-2018-7738    |          | 2.31.1-0.4ubuntu3.6                 | 2.31.1-0.4ubuntu3.7                 | util-linux: Shell command                      |
|                      |                  |          |                                     |                                     | injection in unescaped                         |
|                      |                  |          |                                     |                                     | bash-completed mount point names               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7738           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libfreetype6         | CVE-2020-15999   | HIGH     | 2.8.1-2ubuntu2                      | 2.8.1-2ubuntu2.1                    | freetype: Heap-based buffer                    |
|                      |                  |          |                                     |                                     | overflow due to integer                        |
|                      |                  |          |                                     |                                     | truncation in Load_SBit_Png                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-15999          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libgcc1              | CVE-2020-13844   | MEDIUM   | 8.4.0-1ubuntu1~18.04                |                                     | kernel: ARM straight-line                      |
|                      |                  |          |                                     |                                     | speculation vulnerability                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-13844          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libgcrypt20          | CVE-2021-40528   |          | 1.8.1-4ubuntu1.2                    | 1.8.1-4ubuntu1.3                    | libgcrypt: ElGamal implementation              |
|                      |                  |          |                                     |                                     | allows plaintext recovery                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-40528          |
+                      +------------------+----------+                                     +                                     +------------------------------------------------+
|                      | CVE-2021-33560   | LOW      |                                     |                                     | libgcrypt: mishandles ElGamal                  |
|                      |                  |          |                                     |                                     | encryption because it lacks                    |
|                      |                  |          |                                     |                                     | exponent blinding to address a...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-33560          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libgnutls30          | CVE-2018-16868   |          | 3.5.18-1ubuntu1.3                   |                                     | gnutls: Bleichenbacher-like side               |
|                      |                  |          |                                     |                                     | channel leakage in PKCS#1 v1.5                 |
|                      |                  |          |                                     |                                     | verification and padding oracle...             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-16868          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libgssapi-krb5-2     | CVE-2018-20217   | MEDIUM   | 1.16-2ubuntu0.1                     |                                     | krb5: Reachable assertion in                   |
|                      |                  |          |                                     |                                     | the KDC using S4U2Self requests                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-20217          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-28196   |          |                                     | 1.16-2ubuntu0.2                     | krb5: unbounded recursion via an               |
|                      |                  |          |                                     |                                     | ASN.1-encoded Kerberos message                 |
|                      |                  |          |                                     |                                     | in lib/krb5/asn.1/asn1_encode.c                |
|                      |                  |          |                                     |                                     | may lead...                                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-28196          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-36222   |          |                                     |                                     | krb5: Sending a request containing             |
|                      |                  |          |                                     |                                     | PA-ENCRYPTED-CHALLENGE padata                  |
|                      |                  |          |                                     |                                     | element without using FAST could...            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-36222          |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-5709    | LOW      |                                     |                                     | krb5: integer overflow                         |
|                      |                  |          |                                     |                                     | in dbentry->n_key_data                         |
|                      |                  |          |                                     |                                     | in kadmin/dbutil/dump.c                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-5709           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-5710    |          |                                     |                                     | krb5: null pointer deference                   |
|                      |                  |          |                                     |                                     | in strlen function in                          |
|                      |                  |          |                                     |                                     | plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-5710           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libgssapi3-heimdal   | CVE-2019-12098   |          | 7.5.0+dfsg-1                        |                                     | In the client side of Heimdal before           |
|                      |                  |          |                                     |                                     | 7.6.0, failure to verify anonymou...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-12098          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3671    |          |                                     |                                     | samba: Null pointer dereference                |
|                      |                  |          |                                     |                                     | on missing sname in TGS-REQ                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3671           |
+----------------------+------------------+          +                                     +-------------------------------------+------------------------------------------------+
| libhcrypto4-heimdal  | CVE-2019-12098   |          |                                     |                                     | In the client side of Heimdal before           |
|                      |                  |          |                                     |                                     | 7.6.0, failure to verify anonymou...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-12098          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3671    |          |                                     |                                     | samba: Null pointer dereference                |
|                      |                  |          |                                     |                                     | on missing sname in TGS-REQ                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3671           |
+----------------------+------------------+          +                                     +-------------------------------------+------------------------------------------------+
| libheimbase1-heimdal | CVE-2019-12098   |          |                                     |                                     | In the client side of Heimdal before           |
|                      |                  |          |                                     |                                     | 7.6.0, failure to verify anonymou...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-12098          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3671    |          |                                     |                                     | samba: Null pointer dereference                |
|                      |                  |          |                                     |                                     | on missing sname in TGS-REQ                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3671           |
+----------------------+------------------+          +                                     +-------------------------------------+------------------------------------------------+
| libheimntlm0-heimdal | CVE-2019-12098   |          |                                     |                                     | In the client side of Heimdal before           |
|                      |                  |          |                                     |                                     | 7.6.0, failure to verify anonymou...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-12098          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3671    |          |                                     |                                     | samba: Null pointer dereference                |
|                      |                  |          |                                     |                                     | on missing sname in TGS-REQ                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3671           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libhogweed4          | CVE-2021-20305   | MEDIUM   | 3.4-1                               | 3.4-1ubuntu0.1                      | nettle: Out of bounds memory                   |
|                      |                  |          |                                     |                                     | access in signature verification               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-20305          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3580    |          |                                     | 3.4.1-0ubuntu0.18.04.1              | nettle: Remote crash                           |
|                      |                  |          |                                     |                                     | in RSA decryption via                          |
|                      |                  |          |                                     |                                     | manipulated ciphertext                         |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3580           |
+                      +------------------+----------+                                     +                                     +------------------------------------------------+
|                      | CVE-2018-16869   | LOW      |                                     |                                     | nettle: Leaky data conversion                  |
|                      |                  |          |                                     |                                     | exposing a manager oracle                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-16869          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libhx509-5-heimdal   | CVE-2019-12098   |          | 7.5.0+dfsg-1                        |                                     | In the client side of Heimdal before           |
|                      |                  |          |                                     |                                     | 7.6.0, failure to verify anonymou...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-12098          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3671    |          |                                     |                                     | samba: Null pointer dereference                |
|                      |                  |          |                                     |                                     | on missing sname in TGS-REQ                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3671           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libk5crypto3         | CVE-2018-20217   | MEDIUM   | 1.16-2ubuntu0.1                     |                                     | krb5: Reachable assertion in                   |
|                      |                  |          |                                     |                                     | the KDC using S4U2Self requests                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-20217          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-28196   |          |                                     | 1.16-2ubuntu0.2                     | krb5: unbounded recursion via an               |
|                      |                  |          |                                     |                                     | ASN.1-encoded Kerberos message                 |
|                      |                  |          |                                     |                                     | in lib/krb5/asn.1/asn1_encode.c                |
|                      |                  |          |                                     |                                     | may lead...                                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-28196          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-36222   |          |                                     |                                     | krb5: Sending a request containing             |
|                      |                  |          |                                     |                                     | PA-ENCRYPTED-CHALLENGE padata                  |
|                      |                  |          |                                     |                                     | element without using FAST could...            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-36222          |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-5709    | LOW      |                                     |                                     | krb5: integer overflow                         |
|                      |                  |          |                                     |                                     | in dbentry->n_key_data                         |
|                      |                  |          |                                     |                                     | in kadmin/dbutil/dump.c                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-5709           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-5710    |          |                                     |                                     | krb5: null pointer deference                   |
|                      |                  |          |                                     |                                     | in strlen function in                          |
|                      |                  |          |                                     |                                     | plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-5710           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libkrb5-26-heimdal   | CVE-2019-12098   |          | 7.5.0+dfsg-1                        |                                     | In the client side of Heimdal before           |
|                      |                  |          |                                     |                                     | 7.6.0, failure to verify anonymou...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-12098          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3671    |          |                                     |                                     | samba: Null pointer dereference                |
|                      |                  |          |                                     |                                     | on missing sname in TGS-REQ                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3671           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libkrb5-3            | CVE-2018-20217   | MEDIUM   | 1.16-2ubuntu0.1                     |                                     | krb5: Reachable assertion in                   |
|                      |                  |          |                                     |                                     | the KDC using S4U2Self requests                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-20217          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-28196   |          |                                     | 1.16-2ubuntu0.2                     | krb5: unbounded recursion via an               |
|                      |                  |          |                                     |                                     | ASN.1-encoded Kerberos message                 |
|                      |                  |          |                                     |                                     | in lib/krb5/asn.1/asn1_encode.c                |
|                      |                  |          |                                     |                                     | may lead...                                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-28196          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-36222   |          |                                     |                                     | krb5: Sending a request containing             |
|                      |                  |          |                                     |                                     | PA-ENCRYPTED-CHALLENGE padata                  |
|                      |                  |          |                                     |                                     | element without using FAST could...            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-36222          |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-5709    | LOW      |                                     |                                     | krb5: integer overflow                         |
|                      |                  |          |                                     |                                     | in dbentry->n_key_data                         |
|                      |                  |          |                                     |                                     | in kadmin/dbutil/dump.c                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-5709           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-5710    |          |                                     |                                     | krb5: null pointer deference                   |
|                      |                  |          |                                     |                                     | in strlen function in                          |
|                      |                  |          |                                     |                                     | plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-5710           |
+----------------------+------------------+----------+                                     +-------------------------------------+------------------------------------------------+
| libkrb5support0      | CVE-2018-20217   | MEDIUM   |                                     |                                     | krb5: Reachable assertion in                   |
|                      |                  |          |                                     |                                     | the KDC using S4U2Self requests                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-20217          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-28196   |          |                                     | 1.16-2ubuntu0.2                     | krb5: unbounded recursion via an               |
|                      |                  |          |                                     |                                     | ASN.1-encoded Kerberos message                 |
|                      |                  |          |                                     |                                     | in lib/krb5/asn.1/asn1_encode.c                |
|                      |                  |          |                                     |                                     | may lead...                                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-28196          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-36222   |          |                                     |                                     | krb5: Sending a request containing             |
|                      |                  |          |                                     |                                     | PA-ENCRYPTED-CHALLENGE padata                  |
|                      |                  |          |                                     |                                     | element without using FAST could...            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-36222          |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-5709    | LOW      |                                     |                                     | krb5: integer overflow                         |
|                      |                  |          |                                     |                                     | in dbentry->n_key_data                         |
|                      |                  |          |                                     |                                     | in kadmin/dbutil/dump.c                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-5709           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-5710    |          |                                     |                                     | krb5: null pointer deference                   |
|                      |                  |          |                                     |                                     | in strlen function in                          |
|                      |                  |          |                                     |                                     | plugins/kdb/ldap/libkdb_ldap/ldap_principal2.c |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-5710           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libldap-2.4-2        | CVE-2020-25692   | MEDIUM   | 2.4.45+dfsg-1ubuntu1.5              | 2.4.45+dfsg-1ubuntu1.7              | openldap: NULL pointer dereference             |
|                      |                  |          |                                     |                                     | for unauthenticated packet in slapd            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-25692          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-25709   |          |                                     | 2.4.45+dfsg-1ubuntu1.8              | openldap: assertion failure in                 |
|                      |                  |          |                                     |                                     | Certificate List syntax validation             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-25709          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-25710   |          |                                     |                                     | openldap: assertion failure in CSN             |
|                      |                  |          |                                     |                                     | normalization with invalid input               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-25710          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-36221   |          |                                     | 2.4.45+dfsg-1ubuntu1.9              | openldap: Integer underflow                    |
|                      |                  |          |                                     |                                     | in serialNumberAndIssuerCheck                  |
|                      |                  |          |                                     |                                     | in schema_init.c                               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36221          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36222   |          |                                     |                                     | openldap: Assertion failure in                 |
|                      |                  |          |                                     |                                     | slapd in the saslAuthzTo validation            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36222          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36223   |          |                                     |                                     | openldap: Out-of-bounds                        |
|                      |                  |          |                                     |                                     | read in Values Return Filter                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36223          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36224   |          |                                     |                                     | openldap: Invalid pointer free                 |
|                      |                  |          |                                     |                                     | in the saslAuthzTo processing                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36224          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36225   |          |                                     |                                     | openldap: Double free in                       |
|                      |                  |          |                                     |                                     | the saslAuthzTo processing                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36225          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36226   |          |                                     |                                     | openldap: Denial of service                    |
|                      |                  |          |                                     |                                     | via length miscalculation                      |
|                      |                  |          |                                     |                                     | in slap_parse_user                             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36226          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36227   |          |                                     |                                     | openldap: Infinite loop in slapd with          |
|                      |                  |          |                                     |                                     | the cancel_extop Cancel operation              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36227          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36228   |          |                                     |                                     | openldap: Integer underflow                    |
|                      |                  |          |                                     |                                     | in issuerAndThisUpdateCheck                    |
|                      |                  |          |                                     |                                     | in schema_init.c                               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36228          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36229   |          |                                     |                                     | openldap: Type confusion                       |
|                      |                  |          |                                     |                                     | in ad_keystring in ad.c                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36229          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36230   |          |                                     |                                     | openldap: Assertion failure in                 |
|                      |                  |          |                                     |                                     | ber_next_element in decode.c                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36230          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-27212   |          |                                     | 2.4.45+dfsg-1ubuntu1.10             | openldap: Assertion                            |
|                      |                  |          |                                     |                                     | failure in slapd in the                        |
|                      |                  |          |                                     |                                     | issuerAndThisUpdateCheck function              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-27212          |
+----------------------+------------------+          +                                     +-------------------------------------+------------------------------------------------+
| libldap-common       | CVE-2020-25692   |          |                                     | 2.4.45+dfsg-1ubuntu1.7              | openldap: NULL pointer dereference             |
|                      |                  |          |                                     |                                     | for unauthenticated packet in slapd            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-25692          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-25709   |          |                                     | 2.4.45+dfsg-1ubuntu1.8              | openldap: assertion failure in                 |
|                      |                  |          |                                     |                                     | Certificate List syntax validation             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-25709          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-25710   |          |                                     |                                     | openldap: assertion failure in CSN             |
|                      |                  |          |                                     |                                     | normalization with invalid input               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-25710          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-36221   |          |                                     | 2.4.45+dfsg-1ubuntu1.9              | openldap: Integer underflow                    |
|                      |                  |          |                                     |                                     | in serialNumberAndIssuerCheck                  |
|                      |                  |          |                                     |                                     | in schema_init.c                               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36221          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36222   |          |                                     |                                     | openldap: Assertion failure in                 |
|                      |                  |          |                                     |                                     | slapd in the saslAuthzTo validation            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36222          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36223   |          |                                     |                                     | openldap: Out-of-bounds                        |
|                      |                  |          |                                     |                                     | read in Values Return Filter                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36223          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36224   |          |                                     |                                     | openldap: Invalid pointer free                 |
|                      |                  |          |                                     |                                     | in the saslAuthzTo processing                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36224          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36225   |          |                                     |                                     | openldap: Double free in                       |
|                      |                  |          |                                     |                                     | the saslAuthzTo processing                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36225          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36226   |          |                                     |                                     | openldap: Denial of service                    |
|                      |                  |          |                                     |                                     | via length miscalculation                      |
|                      |                  |          |                                     |                                     | in slap_parse_user                             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36226          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36227   |          |                                     |                                     | openldap: Infinite loop in slapd with          |
|                      |                  |          |                                     |                                     | the cancel_extop Cancel operation              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36227          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36228   |          |                                     |                                     | openldap: Integer underflow                    |
|                      |                  |          |                                     |                                     | in issuerAndThisUpdateCheck                    |
|                      |                  |          |                                     |                                     | in schema_init.c                               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36228          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36229   |          |                                     |                                     | openldap: Type confusion                       |
|                      |                  |          |                                     |                                     | in ad_keystring in ad.c                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36229          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-36230   |          |                                     |                                     | openldap: Assertion failure in                 |
|                      |                  |          |                                     |                                     | ber_next_element in decode.c                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-36230          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-27212   |          |                                     | 2.4.45+dfsg-1ubuntu1.10             | openldap: Assertion                            |
|                      |                  |          |                                     |                                     | failure in slapd in the                        |
|                      |                  |          |                                     |                                     | issuerAndThisUpdateCheck function              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-27212          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| liblz4-1             | CVE-2021-3520    |          | 0.0~r131-2ubuntu3                   | 0.0~r131-2ubuntu3.1                 | lz4: memory corruption                         |
|                      |                  |          |                                     |                                     | due to an integer overflow                     |
|                      |                  |          |                                     |                                     | bug caused by memmove...                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3520           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libmount1            | CVE-2018-7738    | LOW      | 2.31.1-0.4ubuntu3.6                 | 2.31.1-0.4ubuntu3.7                 | util-linux: Shell command                      |
|                      |                  |          |                                     |                                     | injection in unescaped                         |
|                      |                  |          |                                     |                                     | bash-completed mount point names               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7738           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libncurses5          | CVE-2019-17594   |          | 6.1-1ubuntu1.18.04                  |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the _nc_find_entry                 |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17594          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-17595   |          |                                     |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the fmt_entry                      |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17595          |
+----------------------+------------------+          +                                     +-------------------------------------+------------------------------------------------+
| libncursesw5         | CVE-2019-17594   |          |                                     |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the _nc_find_entry                 |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17594          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-17595   |          |                                     |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the fmt_entry                      |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17595          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libnettle6           | CVE-2021-20305   | MEDIUM   | 3.4-1                               | 3.4-1ubuntu0.1                      | nettle: Out of bounds memory                   |
|                      |                  |          |                                     |                                     | access in signature verification               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-20305          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3580    |          |                                     | 3.4.1-0ubuntu0.18.04.1              | nettle: Remote crash                           |
|                      |                  |          |                                     |                                     | in RSA decryption via                          |
|                      |                  |          |                                     |                                     | manipulated ciphertext                         |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3580           |
+                      +------------------+----------+                                     +                                     +------------------------------------------------+
|                      | CVE-2018-16869   | LOW      |                                     |                                     | nettle: Leaky data conversion                  |
|                      |                  |          |                                     |                                     | exposing a manager oracle                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-16869          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libnghttp2-14        | CVE-2019-9511    | MEDIUM   | 1.30.0-1ubuntu1                     |                                     | HTTP/2: large amount of data                   |
|                      |                  |          |                                     |                                     | requests leads to denial of service            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-9511           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-9513    |          |                                     |                                     | HTTP/2: flood using PRIORITY                   |
|                      |                  |          |                                     |                                     | frames results in excessive                    |
|                      |                  |          |                                     |                                     | resource consumption                           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-9513           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libp11-kit0          | CVE-2020-29361   |          | 0.23.9-2                            | 0.23.9-2ubuntu0.1                   | p11-kit: integer overflow when                 |
|                      |                  |          |                                     |                                     | allocating memory for arrays                   |
|                      |                  |          |                                     |                                     | or attributes and object...                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-29361          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-29362   |          |                                     |                                     | p11-kit: out-of-bounds read in                 |
|                      |                  |          |                                     |                                     | p11_rpc_buffer_get_byte_array                  |
|                      |                  |          |                                     |                                     | function in rpc-message.c                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-29362          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-29363   |          |                                     |                                     | p11-kit: out-of-bounds write in                |
|                      |                  |          |                                     |                                     | p11_rpc_buffer_get_byte_array_value            |
|                      |                  |          |                                     |                                     | function in rpc-message.c                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-29363          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libpcre3             | CVE-2017-11164   | LOW      | 2:8.39-9                            |                                     | pcre: OP_KETRMAX feature in the                |
|                      |                  |          |                                     |                                     | match function in pcre_exec.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2017-11164          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-20838   |          |                                     |                                     | pcre: Buffer over-read in JIT                  |
|                      |                  |          |                                     |                                     | when UTF is disabled and \X or...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-20838          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-14155   |          |                                     |                                     | pcre: Integer overflow when                    |
|                      |                  |          |                                     |                                     | parsing callout numeric arguments              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-14155          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libpng16-16          | CVE-2018-14048   |          | 1.6.34-1ubuntu0.18.04.2             |                                     | libpng: Segmentation fault in                  |
|                      |                  |          |                                     |                                     | png.c:png_free_data function                   |
|                      |                  |          |                                     |                                     | causing denial of service                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-14048          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libroken18-heimdal   | CVE-2019-12098   |          | 7.5.0+dfsg-1                        |                                     | In the client side of Heimdal before           |
|                      |                  |          |                                     |                                     | 7.6.0, failure to verify anonymou...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-12098          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3671    |          |                                     |                                     | samba: Null pointer dereference                |
|                      |                  |          |                                     |                                     | on missing sname in TGS-REQ                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3671           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libsasl2-2           | CVE-2022-24407   | HIGH     | 2.1.27~101-g0780600+dfsg-3ubuntu2.1 | 2.1.27~101-g0780600+dfsg-3ubuntu2.4 | cyrus-sasl: failure to properly                |
|                      |                  |          |                                     |                                     | escape SQL input allows                        |
|                      |                  |          |                                     |                                     | an attacker to execute...                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-24407          |
+----------------------+                  +          +                                     +                                     +                                                +
| libsasl2-modules-db  |                  |          |                                     |                                     |                                                |
|                      |                  |          |                                     |                                     |                                                |
|                      |                  |          |                                     |                                     |                                                |
|                      |                  |          |                                     |                                     |                                                |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libsepol1            | CVE-2021-36084   | LOW      | 2.7-1                               |                                     | libsepol: use-after-free in                    |
|                      |                  |          |                                     |                                     | __cil_verify_classperms()                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-36084          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-36085   |          |                                     |                                     | libsepol: use-after-free in                    |
|                      |                  |          |                                     |                                     | __cil_verify_classperms()                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-36085          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-36086   |          |                                     |                                     | libsepol: use-after-free in                    |
|                      |                  |          |                                     |                                     | cil_reset_classpermission()                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-36086          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-36087   |          |                                     |                                     | libsepol: heap-based buffer                    |
|                      |                  |          |                                     |                                     | overflow in ebitmap_match_any()                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-36087          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libsmartcols1        | CVE-2018-7738    |          | 2.31.1-0.4ubuntu3.6                 | 2.31.1-0.4ubuntu3.7                 | util-linux: Shell command                      |
|                      |                  |          |                                     |                                     | injection in unescaped                         |
|                      |                  |          |                                     |                                     | bash-completed mount point names               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7738           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libsqlite3-0         | CVE-2020-9794    | MEDIUM   | 3.22.0-1ubuntu0.4                   |                                     | An out-of-bounds read was                      |
|                      |                  |          |                                     |                                     | addressed with improved bounds                 |
|                      |                  |          |                                     |                                     | checking. This issue is...                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-9794           |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-9849    | LOW      |                                     |                                     | An information disclosure issue                |
|                      |                  |          |                                     |                                     | was addressed with improved                    |
|                      |                  |          |                                     |                                     | state management. This issue...                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-9849           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-9991    |          |                                     |                                     | This issue was addressed                       |
|                      |                  |          |                                     |                                     | with improved checks.                          |
|                      |                  |          |                                     |                                     | This issue is fixed in...                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-9991           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-36690   |          |                                     |                                     | ** DISPUTED ** A segmentation fault            |
|                      |                  |          |                                     |                                     | can occur in the sqlite3.exe comma...          |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-36690          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libssl1.1            | CVE-2020-1971    | HIGH     | 1.1.1-1ubuntu2.1~18.04.6            | 1.1.1-1ubuntu2.1~18.04.7            | openssl: EDIPARTYNAME                          |
|                      |                  |          |                                     |                                     | NULL pointer de-reference                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-1971           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3449    |          |                                     | 1.1.1-1ubuntu2.1~18.04.9            | openssl: NULL pointer dereference              |
|                      |                  |          |                                     |                                     | in signature_algorithms processing             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3449           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3711    |          |                                     | 1.1.1-1ubuntu2.1~18.04.13           | openssl: SM2 Decryption                        |
|                      |                  |          |                                     |                                     | Buffer Overflow                                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3711           |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-23841   | MEDIUM   |                                     | 1.1.1-1ubuntu2.1~18.04.8            | openssl: NULL pointer dereference              |
|                      |                  |          |                                     |                                     | in X509_issuer_and_serial_hash()               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-23841          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3712    |          |                                     | 1.1.1-1ubuntu2.1~18.04.13           | openssl: Read buffer overruns                  |
|                      |                  |          |                                     |                                     | processing ASN.1 strings                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3712           |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-23840   | LOW      |                                     | 1.1.1-1ubuntu2.1~18.04.8            | openssl: integer                               |
|                      |                  |          |                                     |                                     | overflow in CipherUpdate                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-23840          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libstdc++6           | CVE-2020-13844   | MEDIUM   | 8.4.0-1ubuntu1~18.04                |                                     | kernel: ARM straight-line                      |
|                      |                  |          |                                     |                                     | speculation vulnerability                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-13844          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libsystemd0          | CVE-2021-33910   | HIGH     | 237-3ubuntu10.41                    | 237-3ubuntu10.49                    | systemd: uncontrolled                          |
|                      |                  |          |                                     |                                     | allocation on the stack in                     |
|                      |                  |          |                                     |                                     | function unit_name_path_escape                 |
|                      |                  |          |                                     |                                     | leads to crash...                              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-33910          |
+                      +------------------+----------+                                     +                                     +------------------------------------------------+
|                      | CVE-2020-13529   | LOW      |                                     |                                     | systemd: DHCP FORCERENEW                       |
|                      |                  |          |                                     |                                     | authentication not implemented                 |
|                      |                  |          |                                     |                                     | can cause a system running the...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-13529          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libtasn1-6           | CVE-2018-1000654 |          | 4.13-2                              |                                     | libtasn1: Infinite loop in                     |
|                      |                  |          |                                     |                                     | _asn1_expand_object_id(ptree)                  |
|                      |                  |          |                                     |                                     | leads to memory exhaustion                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-1000654        |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libtinfo5            | CVE-2019-17594   |          | 6.1-1ubuntu1.18.04                  |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the _nc_find_entry                 |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17594          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-17595   |          |                                     |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the fmt_entry                      |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17595          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libudev1             | CVE-2021-33910   | HIGH     | 237-3ubuntu10.41                    | 237-3ubuntu10.49                    | systemd: uncontrolled                          |
|                      |                  |          |                                     |                                     | allocation on the stack in                     |
|                      |                  |          |                                     |                                     | function unit_name_path_escape                 |
|                      |                  |          |                                     |                                     | leads to crash...                              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-33910          |
+                      +------------------+----------+                                     +                                     +------------------------------------------------+
|                      | CVE-2020-13529   | LOW      |                                     |                                     | systemd: DHCP FORCERENEW                       |
|                      |                  |          |                                     |                                     | authentication not implemented                 |
|                      |                  |          |                                     |                                     | can cause a system running the...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-13529          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libuuid1             | CVE-2018-7738    |          | 2.31.1-0.4ubuntu3.6                 | 2.31.1-0.4ubuntu3.7                 | util-linux: Shell command                      |
|                      |                  |          |                                     |                                     | injection in unescaped                         |
|                      |                  |          |                                     |                                     | bash-completed mount point names               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7738           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| libwind0-heimdal     | CVE-2019-12098   |          | 7.5.0+dfsg-1                        |                                     | In the client side of Heimdal before           |
|                      |                  |          |                                     |                                     | 7.6.0, failure to verify anonymou...           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-12098          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3671    |          |                                     |                                     | samba: Null pointer dereference                |
|                      |                  |          |                                     |                                     | on missing sname in TGS-REQ                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3671           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| libzstd1             | CVE-2021-24031   | MEDIUM   | 1.3.3+dfsg-2ubuntu1.1               | 1.3.3+dfsg-2ubuntu1.2               | zstd: adds read permissions                    |
|                      |                  |          |                                     |                                     | to files while being                           |
|                      |                  |          |                                     |                                     | compressed or uncompressed                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-24031          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-24032   |          |                                     |                                     | zstd: Race condition                           |
|                      |                  |          |                                     |                                     | allows attacker to access                      |
|                      |                  |          |                                     |                                     | world-readable destination file                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-24032          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| locales              | CVE-2018-11236   |          | 2.27-3ubuntu1                       | 2.27-3ubuntu1.2                     | glibc: Integer overflow in                     |
|                      |                  |          |                                     |                                     | stdlib/canonicalize.c on                       |
|                      |                  |          |                                     |                                     | 32-bit architectures leading                   |
|                      |                  |          |                                     |                                     | to stack-based buffer...                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-11236          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2018-11237   |          |                                     |                                     | glibc: Buffer overflow in                      |
|                      |                  |          |                                     |                                     | __mempcpy_avx512_no_vzeroupper                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-11237          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2018-19591   |          |                                     |                                     | glibc: file descriptor                         |
|                      |                  |          |                                     |                                     | leak in if_nametoindex() in                    |
|                      |                  |          |                                     |                                     | sysdeps/unix/sysv/linux/if_index.c             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-19591          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-1751    |          |                                     |                                     | glibc: array overflow in                       |
|                      |                  |          |                                     |                                     | backtrace functions for powerpc                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-1751           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3999    |          |                                     | 2.27-3ubuntu1.5                     | glibc: Off-by-one buffer                       |
|                      |                  |          |                                     |                                     | overflow/underflow in getcwd()                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3999           |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2009-5155    | LOW      |                                     |                                     | glibc: parse_reg_exp in                        |
|                      |                  |          |                                     |                                     | posix/regcomp.c misparses                      |
|                      |                  |          |                                     |                                     | alternatives leading to                        |
|                      |                  |          |                                     |                                     | denial of service or...                        |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2009-5155           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2015-8985    |          |                                     |                                     | glibc: potential denial of                     |
|                      |                  |          |                                     |                                     | service in pop_fail_stack()                    |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2015-8985           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2016-10228   |          |                                     | 2.27-3ubuntu1.5                     | glibc: iconv program can hang                  |
|                      |                  |          |                                     |                                     | when invoked with the -c option                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2016-10228          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2016-10739   |          |                                     |                                     | glibc: getaddrinfo should reject IP            |
|                      |                  |          |                                     |                                     | addresses with trailing characters             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2016-10739          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-19126   |          |                                     | 2.27-3ubuntu1.2                     | glibc: LD_PREFER_MAP_32BIT_EXEC                |
|                      |                  |          |                                     |                                     | not ignored in setuid binaries                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-19126          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-25013   |          |                                     | 2.27-3ubuntu1.5                     | glibc: buffer over-read in                     |
|                      |                  |          |                                     |                                     | iconv when processing invalid                  |
|                      |                  |          |                                     |                                     | multi-byte input sequences in...               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-25013          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-9169    |          |                                     | 2.27-3ubuntu1.2                     | glibc: regular-expression                      |
|                      |                  |          |                                     |                                     | match via proceed_next_node                    |
|                      |                  |          |                                     |                                     | in posix/regexec.c leads to                    |
|                      |                  |          |                                     |                                     | heap-based buffer over-read...                 |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-9169           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-10029   |          |                                     |                                     | glibc: stack corruption                        |
|                      |                  |          |                                     |                                     | from crafted input in cosl,                    |
|                      |                  |          |                                     |                                     | sinl, sincosl, and tanl...                     |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-10029          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-1752    |          |                                     |                                     | glibc: use-after-free in glob()                |
|                      |                  |          |                                     |                                     | function when expanding ~user                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-1752           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-27618   |          |                                     | 2.27-3ubuntu1.5                     | glibc: iconv when processing                   |
|                      |                  |          |                                     |                                     | invalid multi-byte input                       |
|                      |                  |          |                                     |                                     | sequences fails to advance the...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-27618          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-29562   |          |                                     |                                     | glibc: assertion failure in iconv              |
|                      |                  |          |                                     |                                     | when converting invalid UCS4                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-29562          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-6096    |          |                                     |                                     | glibc: signed comparison                       |
|                      |                  |          |                                     |                                     | vulnerability in the                           |
|                      |                  |          |                                     |                                     | ARMv7 memcpy function                          |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-6096           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-3326    |          |                                     |                                     | glibc: Assertion failure in                    |
|                      |                  |          |                                     |                                     | ISO-2022-JP-3 gconv module                     |
|                      |                  |          |                                     |                                     | related to combining characters                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3326           |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2021-35942   |          |                                     |                                     | glibc: Arbitrary read in wordexp()             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-35942          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-23218   |          |                                     |                                     | glibc: Stack-based buffer overflow             |
|                      |                  |          |                                     |                                     | in svcunix_create via long pathnames           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-23218          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2022-23219   |          |                                     |                                     | glibc: Stack-based buffer                      |
|                      |                  |          |                                     |                                     | overflow in sunrpc clnt_create                 |
|                      |                  |          |                                     |                                     | via a long pathname                            |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2022-23219          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| login                | CVE-2013-4235    |          | 1:4.5-1ubuntu2                      |                                     | shadow-utils: TOCTOU race                      |
|                      |                  |          |                                     |                                     | conditions by copying and                      |
|                      |                  |          |                                     |                                     | removing directory trees                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2013-4235           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-7169    |          |                                     | 1:4.5-1ubuntu2.2                    | shadow-utils: newgidmap                        |
|                      |                  |          |                                     |                                     | allows unprivileged user to                    |
|                      |                  |          |                                     |                                     | drop supplementary groups                      |
|                      |                  |          |                                     |                                     | potentially allowing privilege...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7169           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| mount                | CVE-2018-7738    |          | 2.31.1-0.4ubuntu3.6                 | 2.31.1-0.4ubuntu3.7                 | util-linux: Shell command                      |
|                      |                  |          |                                     |                                     | injection in unescaped                         |
|                      |                  |          |                                     |                                     | bash-completed mount point names               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7738           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| ncurses-base         | CVE-2019-17594   |          | 6.1-1ubuntu1.18.04                  |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the _nc_find_entry                 |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17594          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-17595   |          |                                     |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the fmt_entry                      |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17595          |
+----------------------+------------------+          +                                     +-------------------------------------+------------------------------------------------+
| ncurses-bin          | CVE-2019-17594   |          |                                     |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the _nc_find_entry                 |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17594          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2019-17595   |          |                                     |                                     | ncurses: heap-based buffer                     |
|                      |                  |          |                                     |                                     | overflow in the fmt_entry                      |
|                      |                  |          |                                     |                                     | function in tinfo/comp_hash.c                  |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-17595          |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| openssl              | CVE-2020-1971    | HIGH     | 1.1.1-1ubuntu2.1~18.04.6            | 1.1.1-1ubuntu2.1~18.04.7            | openssl: EDIPARTYNAME                          |
|                      |                  |          |                                     |                                     | NULL pointer de-reference                      |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-1971           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3449    |          |                                     | 1.1.1-1ubuntu2.1~18.04.9            | openssl: NULL pointer dereference              |
|                      |                  |          |                                     |                                     | in signature_algorithms processing             |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3449           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3711    |          |                                     | 1.1.1-1ubuntu2.1~18.04.13           | openssl: SM2 Decryption                        |
|                      |                  |          |                                     |                                     | Buffer Overflow                                |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3711           |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-23841   | MEDIUM   |                                     | 1.1.1-1ubuntu2.1~18.04.8            | openssl: NULL pointer dereference              |
|                      |                  |          |                                     |                                     | in X509_issuer_and_serial_hash()               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-23841          |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-3712    |          |                                     | 1.1.1-1ubuntu2.1~18.04.13           | openssl: Read buffer overruns                  |
|                      |                  |          |                                     |                                     | processing ASN.1 strings                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-3712           |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2021-23840   | LOW      |                                     | 1.1.1-1ubuntu2.1~18.04.8            | openssl: integer                               |
|                      |                  |          |                                     |                                     | overflow in CipherUpdate                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2021-23840          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| passwd               | CVE-2013-4235    |          | 1:4.5-1ubuntu2                      |                                     | shadow-utils: TOCTOU race                      |
|                      |                  |          |                                     |                                     | conditions by copying and                      |
|                      |                  |          |                                     |                                     | removing directory trees                       |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2013-4235           |
+                      +------------------+          +                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2018-7169    |          |                                     | 1:4.5-1ubuntu2.2                    | shadow-utils: newgidmap                        |
|                      |                  |          |                                     |                                     | allows unprivileged user to                    |
|                      |                  |          |                                     |                                     | drop supplementary groups                      |
|                      |                  |          |                                     |                                     | potentially allowing privilege...              |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7169           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+
| perl-base            | CVE-2020-16156   | MEDIUM   | 5.26.1-6ubuntu0.3                   |                                     | perl-CPAN: Bypass of verification              |
|                      |                  |          |                                     |                                     | of signatures in CHECKSUMS files               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-16156          |
+                      +------------------+----------+                                     +-------------------------------------+------------------------------------------------+
|                      | CVE-2020-10543   | LOW      |                                     | 5.26.1-6ubuntu0.5                   | perl: heap-based buffer                        |
|                      |                  |          |                                     |                                     | overflow in regular expression                 |
|                      |                  |          |                                     |                                     | compiler leads to DoS                          |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-10543          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-10878   |          |                                     |                                     | perl: corruption of intermediate               |
|                      |                  |          |                                     |                                     | language state of compiled                     |
|                      |                  |          |                                     |                                     | regular expression due to...                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-10878          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2020-12723   |          |                                     |                                     | perl: corruption of intermediate               |
|                      |                  |          |                                     |                                     | language state of compiled                     |
|                      |                  |          |                                     |                                     | regular expression due to...                   |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2020-12723          |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| tar                  | CVE-2018-20482   |          | 1.29b-2ubuntu0.1                    | 1.29b-2ubuntu0.2                    | tar: Infinite read loop                        |
|                      |                  |          |                                     |                                     | in sparse_dump_region                          |
|                      |                  |          |                                     |                                     | function in sparse.c                           |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-20482          |
+                      +------------------+          +                                     +                                     +------------------------------------------------+
|                      | CVE-2019-9923    |          |                                     |                                     | tar: null-pointer dereference                  |
|                      |                  |          |                                     |                                     | in pax_decode_header in sparse.c               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2019-9923           |
+----------------------+------------------+          +-------------------------------------+-------------------------------------+------------------------------------------------+
| util-linux           | CVE-2018-7738    |          | 2.31.1-0.4ubuntu3.6                 | 2.31.1-0.4ubuntu3.7                 | util-linux: Shell command                      |
|                      |                  |          |                                     |                                     | injection in unescaped                         |
|                      |                  |          |                                     |                                     | bash-completed mount point names               |
|                      |                  |          |                                     |                                     | -->avd.aquasec.com/nvd/cve-2018-7738           |
+----------------------+------------------+----------+-------------------------------------+-------------------------------------+------------------------------------------------+

Java (jar)
==========
Total: 5 (UNKNOWN: 1, LOW: 0, MEDIUM: 1, HIGH: 0, CRITICAL: 3)

+-----------------------------------+------------------+----------+-------------------+--------------------------------+---------------------------------------+
|              LIBRARY              | VULNERABILITY ID | SEVERITY | INSTALLED VERSION |         FIXED VERSION          |                 TITLE                 |
+-----------------------------------+------------------+----------+-------------------+--------------------------------+---------------------------------------+
| com.h2database:h2                 | CVE-2021-23463   | CRITICAL | 1.3.176           | 2.0.202                        | h2database: XXE                       |
|                                   |                  |          |                   |                                | injection vulnerability               |
|                                   |                  |          |                   |                                | -->avd.aquasec.com/nvd/cve-2021-23463 |
+                                   +------------------+          +                   +--------------------------------+---------------------------------------+
|                                   | CVE-2021-42392   |          |                   | 2.0.206                        | h2: Remote Code Execution in Console  |
|                                   |                  |          |                   |                                | -->avd.aquasec.com/nvd/cve-2021-42392 |
+                                   +------------------+          +                   +--------------------------------+---------------------------------------+
|                                   | CVE-2022-23221   |          |                   | 2.1.210                        | h2: Loading of custom classes         |
|                                   |                  |          |                   |                                | from remote servers through JNDI      |
|                                   |                  |          |                   |                                | -->avd.aquasec.com/nvd/cve-2022-23221 |
+                                   +------------------+----------+                   +--------------------------------+---------------------------------------+
|                                   | GMS-2022-7       | UNKNOWN  |                   | 2.0.206                        | Improper Neutralization of            |
|                                   |                  |          |                   |                                | Special Elements used in an OS        |
|                                   |                  |          |                   |                                | Command ('OS Command...               |
+-----------------------------------+------------------+----------+-------------------+--------------------------------+---------------------------------------+
| org.hibernate:hibernate-validator | CVE-2020-10693   | MEDIUM   | 5.3.6.Final       | 6.0.20.Final, 6.1.5.Final,     | hibernate-validator: Improper input   |
|                                   |                  |          |                   | 7.0.0.CR1                      | validation in the interpolation       |
|                                   |                  |          |                   |                                | of constraint error messages          |
|                                   |                  |          |                   |                                | -->avd.aquasec.com/nvd/cve-2020-10693 |
+-----------------------------------+------------------+----------+-------------------+--------------------------------+---------------------------------------+
```