# Docker

# Build

To build the Docker image, navigate to the parent directory and run the following command:
```
docker build -t holo -f docker/Dockerfile .
```

By default, the build will use the `release` profile. If you want to build with a different profile, you can specify it using the `--build-arg` flag:
```
docker build --build-arg BUILD_PROFILE=dev -t holo -f docker/Dockerfile .
```

Available build profiles:
- `release` (default): Optimized for production.
- `dev`: For development with debugging info.
- `small`: For smaller binaries.

# Running

To run the container in the background, use the following command:
```
docker run -itd --privileged --name holo holo
```

To access Holo's CLI, use the following command:
```
docker exec -it holo holo-cli
