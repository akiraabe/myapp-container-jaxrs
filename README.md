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
2022-03-10T09:44:16.859+0900	[34mINFO[0m	Need to update DB
2022-03-10T09:44:16.859+0900	[34mINFO[0m	Downloading DB...
2022-03-10T09:45:15.178+0900	[34mINFO[0m	Detected OS: ubuntu
2022-03-10T09:45:15.178+0900	[34mINFO[0m	Detecting Ubuntu vulnerabilities...
2022-03-10T09:45:15.180+0900	[34mINFO[0m	Number of language-specific files: 1
2022-03-10T09:45:15.180+0900	[34mINFO[0m	Detecting jar vulnerabilities...

myapp-container-jaxrs:0.1.0 (ubuntu 20.04)
==========================================
Total: 36 (UNKNOWN: 0, LOW: 29, MEDIUM: 7, HIGH: 0, CRITICAL: 0)

+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
|       LIBRARY        | VULNERABILITY ID | SEVERITY |    INSTALLED VERSION     | FIXED VERSION |                  TITLE                  |
+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
| bash                 | CVE-2019-18276   | LOW      | 5.0-6ubuntu1.1           |               | bash: when effective UID is not         |
|                      |                  |          |                          |               | equal to its real UID the...            |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2019-18276   |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| coreutils            | CVE-2016-2781    |          | 8.30-3ubuntu2            |               | coreutils: Non-privileged               |
|                      |                  |          |                          |               | session can escape to the               |
|                      |                  |          |                          |               | parent session in chroot                |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2016-2781    |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| libasn1-8-heimdal    | CVE-2021-3671    |          | 7.7.0+dfsg-1ubuntu1      |               | samba: Null pointer dereference         |
|                      |                  |          |                          |               | on missing sname in TGS-REQ             |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-3671    |
+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
| libexpat1            | CVE-2022-25314   | MEDIUM   | 2.2.9-1ubuntu0.2         |               | expat: integer overflow                 |
|                      |                  |          |                          |               | in copyString()                         |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2022-25314   |
+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
| libgmp10             | CVE-2021-43618   | LOW      | 2:6.2.0+dfsg-4           |               | gmp: Integer overflow and resultant     |
|                      |                  |          |                          |               | buffer overflow via crafted input       |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-43618   |
+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
| libgssapi-krb5-2     | CVE-2021-36222   | MEDIUM   | 1.17-6ubuntu4.1          |               | krb5: Sending a request containing      |
|                      |                  |          |                          |               | PA-ENCRYPTED-CHALLENGE padata           |
|                      |                  |          |                          |               | element without using FAST could...     |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-36222   |
+                      +------------------+----------+                          +---------------+-----------------------------------------+
|                      | CVE-2018-5709    | LOW      |                          |               | krb5: integer overflow                  |
|                      |                  |          |                          |               | in dbentry->n_key_data                  |
|                      |                  |          |                          |               | in kadmin/dbutil/dump.c                 |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2018-5709    |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| libgssapi3-heimdal   | CVE-2021-3671    |          | 7.7.0+dfsg-1ubuntu1      |               | samba: Null pointer dereference         |
|                      |                  |          |                          |               | on missing sname in TGS-REQ             |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-3671    |
+----------------------+                  +          +                          +---------------+                                         +
| libhcrypto4-heimdal  |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
+----------------------+                  +          +                          +---------------+                                         +
| libheimbase1-heimdal |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
+----------------------+                  +          +                          +---------------+                                         +
| libheimntlm0-heimdal |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
+----------------------+                  +          +                          +---------------+                                         +
| libhx509-5-heimdal   |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
| libk5crypto3         | CVE-2021-36222   | MEDIUM   | 1.17-6ubuntu4.1          |               | krb5: Sending a request containing      |
|                      |                  |          |                          |               | PA-ENCRYPTED-CHALLENGE padata           |
|                      |                  |          |                          |               | element without using FAST could...     |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-36222   |
+                      +------------------+----------+                          +---------------+-----------------------------------------+
|                      | CVE-2018-5709    | LOW      |                          |               | krb5: integer overflow                  |
|                      |                  |          |                          |               | in dbentry->n_key_data                  |
|                      |                  |          |                          |               | in kadmin/dbutil/dump.c                 |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2018-5709    |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| libkrb5-26-heimdal   | CVE-2021-3671    |          | 7.7.0+dfsg-1ubuntu1      |               | samba: Null pointer dereference         |
|                      |                  |          |                          |               | on missing sname in TGS-REQ             |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-3671    |
+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
| libkrb5-3            | CVE-2021-36222   | MEDIUM   | 1.17-6ubuntu4.1          |               | krb5: Sending a request containing      |
|                      |                  |          |                          |               | PA-ENCRYPTED-CHALLENGE padata           |
|                      |                  |          |                          |               | element without using FAST could...     |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-36222   |
+                      +------------------+----------+                          +---------------+-----------------------------------------+
|                      | CVE-2018-5709    | LOW      |                          |               | krb5: integer overflow                  |
|                      |                  |          |                          |               | in dbentry->n_key_data                  |
|                      |                  |          |                          |               | in kadmin/dbutil/dump.c                 |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2018-5709    |
+----------------------+------------------+----------+                          +---------------+-----------------------------------------+
| libkrb5support0      | CVE-2021-36222   | MEDIUM   |                          |               | krb5: Sending a request containing      |
|                      |                  |          |                          |               | PA-ENCRYPTED-CHALLENGE padata           |
|                      |                  |          |                          |               | element without using FAST could...     |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-36222   |
+                      +------------------+----------+                          +---------------+-----------------------------------------+
|                      | CVE-2018-5709    | LOW      |                          |               | krb5: integer overflow                  |
|                      |                  |          |                          |               | in dbentry->n_key_data                  |
|                      |                  |          |                          |               | in kadmin/dbutil/dump.c                 |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2018-5709    |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| libpcre3             | CVE-2017-11164   |          | 2:8.39-12build1          |               | pcre: OP_KETRMAX feature in the         |
|                      |                  |          |                          |               | match function in pcre_exec.c           |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2017-11164   |
+                      +------------------+          +                          +---------------+-----------------------------------------+
|                      | CVE-2019-20838   |          |                          |               | pcre: Buffer over-read in JIT           |
|                      |                  |          |                          |               | when UTF is disabled and \X or...       |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2019-20838   |
+                      +------------------+          +                          +---------------+-----------------------------------------+
|                      | CVE-2020-14155   |          |                          |               | pcre: Integer overflow when             |
|                      |                  |          |                          |               | parsing callout numeric arguments       |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2020-14155   |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| libroken18-heimdal   | CVE-2021-3671    |          | 7.7.0+dfsg-1ubuntu1      |               | samba: Null pointer dereference         |
|                      |                  |          |                          |               | on missing sname in TGS-REQ             |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-3671    |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| libsepol1            | CVE-2021-36084   |          | 3.0-1                    |               | libsepol: use-after-free in             |
|                      |                  |          |                          |               | __cil_verify_classperms()               |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-36084   |
+                      +------------------+          +                          +---------------+-----------------------------------------+
|                      | CVE-2021-36085   |          |                          |               | libsepol: use-after-free in             |
|                      |                  |          |                          |               | __cil_verify_classperms()               |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-36085   |
+                      +------------------+          +                          +---------------+-----------------------------------------+
|                      | CVE-2021-36086   |          |                          |               | libsepol: use-after-free in             |
|                      |                  |          |                          |               | cil_reset_classpermission()             |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-36086   |
+                      +------------------+          +                          +---------------+-----------------------------------------+
|                      | CVE-2021-36087   |          |                          |               | libsepol: heap-based buffer             |
|                      |                  |          |                          |               | overflow in ebitmap_match_any()         |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-36087   |
+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
| libsqlite3-0         | CVE-2020-9794    | MEDIUM   | 3.31.1-4ubuntu0.2        |               | An out-of-bounds read was               |
|                      |                  |          |                          |               | addressed with improved bounds          |
|                      |                  |          |                          |               | checking. This issue is...              |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2020-9794    |
+                      +------------------+----------+                          +---------------+-----------------------------------------+
|                      | CVE-2020-9849    | LOW      |                          |               | An information disclosure issue         |
|                      |                  |          |                          |               | was addressed with improved             |
|                      |                  |          |                          |               | state management. This issue...         |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2020-9849    |
+                      +------------------+          +                          +---------------+-----------------------------------------+
|                      | CVE-2020-9991    |          |                          |               | This issue was addressed                |
|                      |                  |          |                          |               | with improved checks.                   |
|                      |                  |          |                          |               | This issue is fixed in...               |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2020-9991    |
+                      +------------------+          +                          +---------------+-----------------------------------------+
|                      | CVE-2021-36690   |          |                          |               | ** DISPUTED ** A segmentation fault     |
|                      |                  |          |                          |               | can occur in the sqlite3.exe comma...   |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-36690   |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| libtasn1-6           | CVE-2018-1000654 |          | 4.16.0-2                 |               | libtasn1: Infinite loop in              |
|                      |                  |          |                          |               | _asn1_expand_object_id(ptree)           |
|                      |                  |          |                          |               | leads to memory exhaustion              |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2018-1000654 |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| libwind0-heimdal     | CVE-2021-3671    |          | 7.7.0+dfsg-1ubuntu1      |               | samba: Null pointer dereference         |
|                      |                  |          |                          |               | on missing sname in TGS-REQ             |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2021-3671    |
+----------------------+------------------+          +--------------------------+---------------+-----------------------------------------+
| login                | CVE-2013-4235    |          | 1:4.8.1-1ubuntu5.20.04.1 |               | shadow-utils: TOCTOU race               |
|                      |                  |          |                          |               | conditions by copying and               |
|                      |                  |          |                          |               | removing directory trees                |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2013-4235    |
+----------------------+                  +          +                          +---------------+                                         +
| passwd               |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
|                      |                  |          |                          |               |                                         |
+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+
| perl-base            | CVE-2020-16156   | MEDIUM   | 5.30.0-9ubuntu0.2        |               | perl-CPAN: Bypass of verification       |
|                      |                  |          |                          |               | of signatures in CHECKSUMS files        |
|                      |                  |          |                          |               | -->avd.aquasec.com/nvd/cve-2020-16156   |
+----------------------+------------------+----------+--------------------------+---------------+-----------------------------------------+

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