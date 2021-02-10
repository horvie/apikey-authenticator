# apikey-authenticator
Validates client based on API key sent either in 'Authorization: Apikey' header or 'apikey' request parameter (query or form).
User must have this key stored in attribute with name 'apikey'.

# Deployment
```shell script
mvn clean package
cp target/*.jar $KEYCLOAK_HOME/standalone/deployments/
```

# Keycloak Configuration

1. Go to Authentication menu
2. Create or edit a custom flow
3. Add execution
4. Pick up from the list the Custom Authenticator