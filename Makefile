MODULE=mod_plpgsql
MODULE_NAME=plpgsql
APXS=/usr/bin/apxs

all: $(MODULE)

mod_plpgsql:
	$(APXS) -c -I /usr/pgsql-14/include -L /usr/pgsql-14/lib -lpq -Wc,-g $@.c 

install: $(MODULE)
	$(APXS) -i -a -n $(MODULE_NAME) $(MODULE).la

clean:
	rm -rf *.so *.o *.slo *.la *.lo .libs
