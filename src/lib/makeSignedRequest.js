

    var httpRequest = new AWS.HttpRequest("https://<API_GATE_WAY_ENDPOINT", "<region>");
    httpRequest.headers.host = "<API_GATE_WAY_ENDPOINT>"; // Do not specify http or https!!

    AWS.config.credentials = {
        accessKeyId: creds.Credentials.AccessKeyId,
        secretAccessKey: creds.Credentials.SecretKey,
        sessionToken: creds.Credentials.SessionToken
    }
    httpRequest.method = "POST";
    httpRequest.body = JSON.stringify(data)

    var v4signer = new AWS.Signers.V4(httpRequest, "execute-api");
    v4signer.addAuthorization(AWS.config.credentials, AWS.util.date.getDate());

    const rawResponse = await fetch(httpRequest.endpoint.href , {
        method: httpRequest.method,
        headers: httpRequest.headers,
        body: httpRequest.body
    });