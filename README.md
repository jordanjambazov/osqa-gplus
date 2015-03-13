Google+ Sign-In for OSQA
========================

OSQA Plugin that adds [Pure server-side flow for Google+ Sign-In](https://developers.google.com/+/web/signin/redirect-uri-flow).  
It also converts automatically existing accounts with the old Google OpenID credentials to the Google+ Sign-In without any data-loss.

Installation
------------

1. Clone this repository to some location.
2. Create symbolic link with source as the `gplusauth` folder and target in the `forum_modules`.
3. Generate API keys and download the client secrets file. The file needs to be located in the OSQA root folder and named `client_secrets.json`.
