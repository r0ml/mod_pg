
mod_pg is an Apache module which establishes a PostgreSQL database connection for a session, and allows the browser to execute PostgreSQL api calls for that user.

Configuration is simple.  Include the module by

```
   LoadModule postgresql_module path/to/mod_pg.so
```

and activate it by specifying, in either a directory or virtual server

```
   PostgreSQL stored-procedure db-connection-string
```

The stored-procedure is expected to take five arguments and return a JSON.

The five arguments are:
1) The IP address of the requestor
2) The user-agent string of the requestor (in case the result should be user-agent specific)
3) The session-id of the requestor.  Currently (for legacy reasons) this is the content of JSESSIONID -- but this will be changed in the near future.
4) a string which is currently unused.
5) a JSON which is the contents of the POST of the request (assuming the request is a post).  If the request is a GET, then the JSON passed in as the fifth argument is: `{function: get_path, path: xxx, args: {yyy...} }` where the path (`xxx`) is the script name of the request and where `yyy` is an object with key/value pairs generated from the request parameters.


Known Issues
============

