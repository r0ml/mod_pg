
mod_pg is an Apache module which establishes a PostgreSQL database connection for a session, and allows the browser to execute PostgreSQL api calls for that user.

Configuration is simple.  Include the module by

```
   LoadModule postgresql_module path/to/mod_pg.so
```

and activate it by specifying, in either a directory or virtual server

```
   PostgreSQL stored-procedure db-connection-string
```

The stored-procedure is expected to take two arguments (in JSON format) and return a JSON.

The first argument is a JSON object specifying metadata for the query.  The second argument is a JSON which is the contents of the POST of the request (assuming the request is a post).  If the request is a GET, then the JSON passed in as the second argument is: `{function: get_path, path: xxx, args: {yyy...} }` where the path (`xxx`) is the script name of the request and where `yyy` is an object with key/value pairs generated from the request parameters.

The metadata object is constructed by creating an empty object and then inserting the `ip_address` of the requestor.  Following that, selected request headers and cookies will be inserted into the metadata object.  One configures these by specifying the following options:

```
   PostgresHeader header-name key-name
   PostgresCookie cookie-name key-name
```

`PostgresHeader` options will specify a request header and a JSON object key.  The value of the specified header will be inserted into the object with the specified key.  If the `key-name` is ommitted, the `header-name` will be used.  Multiple `PostgresHeader` options can be specified, and all those request headers will be inserted into the metadata object.  If a request does not contain the header, it will (of course) not be included in the resulting metadata object.

Similarly for `PostgresCookie` -- except the request cookies will be added to the metadata object.

One can override the configured postgres connection string by setting a cookie named `db-connexion`.  If the `db-connexion` cookie is set, those values will be appended to the default connection string -- and that connection opened.  Because of the way PostgreSQL handles connection strings, if the same option is specified multiple times, the last one will be effective.  So, for example, if the connection string is:

``` host=example.com dbname=test dbname=dev ```

the client will connect to the database `dev`.  So, for a PostgreSQL connection string of `host=example.com dbname=test`  by setting the `db-connexion` cookie to `dbname=dev`, the client can temporarily switch to using the `dev` database.

Known Issues
============

- There needs to be a way to disable the `db-connexion` connection string override feature to limit exploits.

