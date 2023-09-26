# Feide Session Sharing for NodeBB

This plugin handles authentication for nodebb based on a bearer token from Feide authentication. It is a fork based 
on the [Session-sharing-plugin](https://github.com/julianlam/nodebb-plugin-session-sharing). 


## How does this work?

This plugin works on API calls and checks the request header for a feideauthentication header. It then checks the Bearer token against the dataporten api for information about the user. This includes both checks for user information, and education affiliation. It then connects the Feide user with a nodebb account and performs the action as this account. If the Feide-user does not have an account it creates a user based on the information gathered from the feide-account, then performs the action with the newly created nodebb account. 