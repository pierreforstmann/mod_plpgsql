# mod_plpgsql

## setup 

Setup instructions are for Alma Linux 8.6.

Install Apache and PostgreSQL development packages:

```
dnf install httpd-devel 2.4.37
dnf install postgresql14-devel
```

If SELinux is enabled:

`setsebool -P httpd_can_network_connect 1`

Add to `/etc/httpd/conf/httpd.conf` section PostgreSQL connection data:

```
<Location /pg/*>
SetHandler plpgsql-handler
PGusername test
PGpassword test
PGhostname localhost
PGPort 5436
PGDatabase test
</Location>
```
Build and install mod_plpgsql Apache module:

```
git clone https://github.com/pierreforstmann/mod_plpgsql.git
cd mod_plpgsql
make
sudo make install

```

Restart Apache:

`sudo apachectl start`

Run in PostgreSQL database:

`psql -h localhost -p 5436 -U test < mod_plpgsql.sql`

## test
Run:
```
$ curl 'http://localhost/pg/print0'
<h3>Hello from PostgreSQL </h3><br>
$ curl 'http://localhost/pg/print1?parm=OK'
<h3>Hello from PostgreSQL: parm=OK</h3><br>
$ curl 'http://localhost/pg/print2?parm1=123&parm2=abc'
<h3>Hello from PostgreSQL: parm1=123 parm2=abc </h3><br>
$ curl 'http://localhost/pg/print2?parm1=abc&parm2=123'
<h3>Hello from PostgreSQL: parm1=abc parm2=123 </h3><br>
```

