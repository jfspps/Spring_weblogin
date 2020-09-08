# This table is specifically for access to the MySQL workbench database (this is not launched automatically)

CREATE DATABASE web_login;

CREATE USER 'SRM_dev_user'@'localhost' IDENTIFIED BY 'admin';
CREATE USER 'SRM_dev_user'@'%' IDENTIFIED BY 'admin';

GRANT SELECT ON web_login.* to 'SRM_dev_user'@'localhost';
GRANT INSERT ON web_login.* to 'SRM_dev_user'@'localhost';
GRANT DELETE ON web_login.* to 'SRM_dev_user'@'localhost';
GRANT UPDATE ON web_login.* to 'SRM_dev_user'@'localhost';

GRANT SELECT ON web_login.* to 'SRM_dev_user'@'%';
GRANT INSERT ON web_login.* to 'SRM_dev_user'@'%';
GRANT DELETE ON web_login.* to 'SRM_dev_user'@'%';
GRANT UPDATE ON web_login.* to 'SRM_dev_user'@'%';

# Don't forget to check the port number with Docker containers!!