# Spring Security and Thymeleaf login template #

Web-login is Spring Security 5 application intended for other Spring based projects, and edited as desired. This project will be integrated with [SRM-Spring](https://github.com/jfspps/SRM-Spring) project, which also comes with instructions regarding the set-up of MySQL in a Docker container. 

Developed with the following technologies:

+ MySQL 8
+ Spring MVC 4 (including Thymeleaf)
+ Maven 3

## Key features ##

+ BCrypt password encryption
+ Variable session length
+ MySQL persistent user accounts and Remember-Me tokens
+ Granular permissions
+ Bootstrap (CSS) and Thymeleaf front-end
+ Example database entity (TestRecord) to demonstrate CRUD operations
+ User account lock-out after repeated failed login attempts

## Project structure ##

### In-memory database ###

There are two implementations of the in-memory service: a HashMap based service, @Profile 'map' and a JPA enabled service, @Profile 'SDjpa'. The latter is the more developed and up to date of the two. The marking 'dev' is required to connect to a persistent MySQL database, so to enable connection to MySQL mark the [application.properties](./src/main/resources/application.properties) file with the 'SDjpa' and 'dev' annotations.

### Database tables and records ###

An SQL script to build the user's database is [here](./src/main/resources/scripts). To build the latest SQL script, enable 'SDjpa' and 'dev', and then uncomment [application-dev.yml](/src/main/resources/application-dev.yml) as directed. Connection to a MySQL daemon is not required when re-building a script.

The data models are defined in [/dbUsers](src/main/java/com/springsecurity/weblogin/model/security). The service methods are declared in [/services/BaseService](./src/main/java/com/springsecurity/weblogin/services/securityServices/BaseService.java) 
interface, and then defined in [/services/map](./src/main/java/com/springsecurity/weblogin/services/map/security) and 
[/services/springDataJPA](./src/main/java/com/springsecurity/weblogin/services/springDataJPA/security) for the HashMap and 
MySQL JPA implementations, respectively. Additional custom methods, respectively, can be declared in [/services/dbUserServices](src/main/java/com/springsecurity/weblogin/services/securityServices)
 and/or [/repositories](./src/main/java/com/springsecurity/weblogin/repositories/security).

A BootStrap class which populates the HashMap and JPA services is provided by [DataLoader](./src/main/java/com/springsecurity/weblogin/bootstrap/security).
 
### Security configuration ###

Initial security options (credentials, authorisation, session cookies and duration) are set in [/config/SecurityConfiguration](./src/main/java/com/springsecurity/weblogin/config/SecurityConfiguration.java) and the aforementioned DataLoader class.
 
MySQL database network port, table, and other credentials are located in [application-dev.yml](./src/main/resources/application-dev.yml). This is enabled by setting @Profile to 'dev'. One will also find the script needed to produce a SQL script based (when connected to a MySQL daemon) on the data models and can be commented out when not required.

