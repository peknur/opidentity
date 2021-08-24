# Service Provider library and example for the OP Identity Service Broker  
__https://github.com/op-developer/Identity-Service-Broker-API__  


This is just my hobby project to get familiar with identity services.


## Example
Example server with test credentials is under `example/httpd` 
```sh
$ make run-example 
```
or directly
```sh
$ cd example/httpd
$ go run main.go
```
## TODO
 - verify that identity token nonce attribute value is equal to the value of the nonce parameter sent in the authentication request
 - more test cases