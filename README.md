# Tasks

## Coding Exercise: Simple OAuth2 Server

### Tasks

- Create a Golang HTTP server that issues JWT Access Tokens ([RFC 7519](https://tools.ietf.org/html/rfc7519)) using Client Credentials Grant with Basic Authentication ([RFC 6749](https://tools.ietf.org/html/rfc6749)) in the `/token` endpoint.
- Sign the tokens with a self-made RS256 key.
- Provide an endpoint to list the signing keys ([RFC 7517](https://tools.ietf.org/html/rfc7517)).
- Provide deployment manifests to deploy the server in a Kubernetes cluster.
- Create an Introspection endpoint ([RFC 7662](https://tools.ietf.org/html/rfc7662)) to introspect the issued JWT Access Tokens.

### Remarks

- Publish the exercise in a git server and grant us access to review it.
- Avoid a single commit with the whole solution; we want to see how the solution was developed incrementally.
- Provide instructions to execute it.

## Prerequisite

Before running the application, ensure you have the following prerequisites:

- **Go 1.24**: Required for making any changes to the project and development.
- **Kubernetes**: Necessary for testing and running the application.
- **kubectl**: Ensure you can run `kubectl` commands to interact with your Kubernetes cluster.

## Run the Application

Assuming you have `kubectl` command available in your system, navigate to the `k8s` folder of the project in your CLI and run:

```sh
kubectl apply -f deployment.yaml
kubectl apply -f service.yaml
```

Forward the port to access the service:

```sh
kubectl port-forward service/oauth2-server 8080:80
```

To ensure it's up and running, check if the pods are running by using the following command:

```sh
kubectl get pods
```

Go to `http://localhost:8080/health` to check if the service is up.

You can access the API documentation at `http://localhost:8080/docs`.
the credential information and how to use the endpoints are described in the doc

## Develop the Application

If you want to change anything in the code, first make the changes and push them to the main branch (or merge them into the main branch if working on a different branch). Wait for the GitHub action to finish pushing the container registry to GHCR.

To apply the new changes:

If your service is already running, delete the pods to automatically restart them with the new image. Run the following command:

```sh
kubectl delete pods -l app=oauth2-server
```

Then, use the port forwarding command from above to to access it.
