# Spring Security and Thymeleaf login template #

Demo web login (in preparation for [Spring_SRM](https://github.com/jfspps/SRM-Spring))

Developed to run with

+ MySQL 8
+ Spring MVC 4 (including Thymeleaf)
+ Maven 3

Both the in-memory h2 (based on a HashMap) and JPA enabled MySQL databases (via Hibernate) can be accessed by setting the profile between 'map'
 and 'SDjpa' services. The SQL script to build the user's database is [here](./src/main/resources/scripts). A single table
 stores the username, password and authorisation (role). 
 
## Project structure ##

Web-login is intended to be incorporated into other Spring based projects, and edited as desired. Initial security options (credentials, authorisation,
 session cookies and duration) are set in [/config/SecurityConfiguration](./src/main/java/com/springsecurity/weblogin/config/SecurityConfiguration.java).
  The model user is defined in [/dbUsers](src/main/java/com/springsecurity/weblogin/model). 

The service methods are declared in [/services/BaseService](./src/main/java/com/springsecurity/weblogin/services/BaseService.java) 
interface, and then defined in [/services/map](./src/main/java/com/springsecurity/weblogin/services/map) and 
[/services/springDataJPA](./src/main/java/com/springsecurity/weblogin/services/springDataJPA) for the h2 HashMap and 
MySQL JPA services, respectively. Additional custom methods, respectively, can be declared in [/services/dbUserServices](src/main/java/com/springsecurity/weblogin/services/securityServices)
 and/or [/repositories](./src/main/java/com/springsecurity/weblogin/repositories).
 
MySQL connection settings are enabled by declaring the 'dev' profile (in addition to 'SDjpa') in [application.properties](./src/main/resources/application.properties).
 MySQL database port, table, and other credentials are located in [application-dev.yml](./src/main/resources/application-dev.yml). 
 In this YAML file, one will also find the script needed to produce a SQL script based on the Users model and can be commented
 out when not required. A first draft copy, appended with commas, is provided in [the scripts directory](./src/main/resources/scripts)

