# mod_plpgsql

## setup (example on Alma Linux 8.6)

Install Apache and PostgreSQL development packages:

```
httpd-devel 2.4.37
postgresql14-devel
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
Build and install mod_plsql Apache module:

```
make
sudo make install

```

Restart apache:

`sudo apachectl start`

Run in PostgreSQL database:

`psql -h localhost -p 5436 -U test < mod_plsql.sql`

Run:
```
curl http://localhost/pg/print
```
You should get:
```
<h3>Hello from PostgreSQL</h3>
```
