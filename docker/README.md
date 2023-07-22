# Docker

# Build

To build the Docker image, navigate to the parent directory and run the following command:
```
docker build -t holo -f docker/Dockerfile .
```

# Running

To run the container in the background, use the following command:
```
docker run -itd --privileged --name holo holo
```

To access Holo's CLI, use the following command:
```
docker exec -it holo holo-cli
